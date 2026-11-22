use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use ed25519_dalek::{Signer, SigningKey};
use xila_package_bundle::{FileHasher, signing_message};
use xila_package_manifest::{
    Application, FORMAT_VERSION, MAX_FILES, Manifest, SCHEMA_URL, SIGNED_DOMAIN, XilaVersion,
};
use xila_package_reader::{Error, StreamingVerifier};
use xila_package_verification::PublicKey;
use xila_package_writer::{SourceFile, write_package};

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static LIVE_BYTES: Cell<isize> = const { Cell::new(0) };
    static PEAK_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct TrackingAllocator;

fn record_alloc(size: usize) {
    TRACKING.with(|active| {
        if active.get() {
            LIVE_BYTES.with(|live| {
                let next = live.get() + size as isize;
                live.set(next);
                if next > 0 {
                    PEAK_BYTES.with(|peak| {
                        let next_unsigned = next as usize;
                        if next_unsigned > peak.get() {
                            peak.set(next_unsigned);
                        }
                    });
                }
            });
        }
    });
}

fn record_dealloc(size: usize) {
    TRACKING.with(|active| {
        if active.get() {
            LIVE_BYTES.with(|live| {
                live.set(live.get() - size as isize);
            });
        }
    });
}

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_alloc(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_alloc(layout.size());
        }
        pointer
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(pointer, layout, new_size) };
        if !next.is_null() {
            record_dealloc(layout.size());
            record_alloc(new_size);
        }
        next
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_dealloc(layout.size());
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

struct HeapMeasurement {
    before_authentication_bytes: usize,
    payload_phase_bytes: usize,
    peak_bytes: usize,
    end_bytes: usize,
}

fn live_bytes() -> usize {
    LIVE_BYTES.with(|live| live.get().max(0) as usize)
}

fn large_manifest_archive(sign: bool) -> (Vec<u8>, PublicKey, usize, usize) {
    let payload_bytes = vec![0x5a_u8; 4096];
    let mut paths = Vec::with_capacity(MAX_FILES);
    let mut files = Vec::with_capacity(MAX_FILES);

    let file_padding = "a".repeat(78);
    for index in 0..MAX_FILES {
        let path = if index == 0 {
            "executables/application.wasm".to_string()
        } else {
            format!("resources/{file_padding}_{index:03}.bin")
        };
        assert!(path.len() <= 200);
        let mut hasher = FileHasher::new(&path).unwrap();
        hasher.update(&payload_bytes).unwrap();
        files.push(hasher.finish().unwrap());
        paths.push(path);
    }

    let manifest = Manifest {
        schema: Some(SCHEMA_URL.to_string()),
        format_version: FORMAT_VERSION,
        name: "community.large-manifest-benchmark".into(),
        version: "1.0.0".into(),
        target: "wasm32-wasip1".into(),
        xila_version: XilaVersion::new(0, 1),
        capabilities: vec![],
        files,
        application: Some(Application {
            entrypoint: paths[0].clone(),
            display_name: "Large Manifest Benchmark".into(),
            icon: String::new(),
            show_in_launcher: true,
        }),
        metadata: None,
    };

    let private = SigningKey::from_bytes(&[9_u8; 32]);
    let public = PublicKey::from_bytes(&private.verifying_key().to_bytes()).unwrap();
    let json = xila_package_manifest::encode(&manifest).unwrap();
    let signed_message_len = SIGNED_DOMAIN.len() + 4 + json.len();
    let signature = private
        .sign(&signing_message(json.as_bytes()).unwrap())
        .to_bytes();

    let sources: Vec<SourceFile<'_>> = paths
        .iter()
        .map(|path| SourceFile {
            path: path.as_str(),
            bytes: payload_bytes.as_slice(),
        })
        .collect();

    let mut archive = Vec::new();
    write_package(
        &mut archive,
        &manifest,
        &sources,
        sign.then_some(&signature),
    )
    .unwrap();

    let manifest_blocks = 1 + json.len().div_ceil(512);
    let signature_blocks = if sign { 2 } else { 0 };
    let first_payload_block = manifest_blocks + signature_blocks;

    (archive, public, signed_message_len, first_payload_block)
}

fn measure_streaming(
    archive: &[u8],
    trusted: Option<&PublicKey>,
    first_payload_block: usize,
) -> (HeapMeasurement, Manifest) {
    LIVE_BYTES.with(|live| live.set(0));
    PEAK_BYTES.with(|peak| peak.set(0));
    TRACKING.with(|active| active.set(true));

    let mut verifier = StreamingVerifier::new(trusted);
    let mut before_authentication_bytes = 0;
    let mut payload_phase_bytes = 0;

    for (block_index, chunk) in archive.as_chunks::<512>().0.iter().enumerate() {
        if block_index == first_payload_block {
            before_authentication_bytes = live_bytes();
        }
        verifier.push(chunk).unwrap();
        if block_index == first_payload_block {
            payload_phase_bytes = live_bytes();
        }
    }

    let end_bytes = live_bytes();
    let peak_bytes = PEAK_BYTES.with(Cell::get);
    let manifest = verifier.finish().unwrap();

    TRACKING.with(|active| active.set(false));

    (
        HeapMeasurement {
            before_authentication_bytes,
            payload_phase_bytes,
            peak_bytes,
            end_bytes,
        },
        manifest,
    )
}

#[test]
fn streaming_verifier_releases_signed_manifest_buffer_during_payload_phase() {
    let (archive, public, signed_message_len, first_payload_block) = large_manifest_archive(true);
    let (measurement, manifest) = measure_streaming(&archive, Some(&public), first_payload_block);

    assert_eq!(manifest.files.len(), MAX_FILES);

    assert!(
        measurement.before_authentication_bytes - measurement.payload_phase_bytes
            >= signed_message_len,
        "expected payload-phase live heap ({}) to drop by at least {} bytes from pre-authentication ({})",
        measurement.payload_phase_bytes,
        signed_message_len,
        measurement.before_authentication_bytes,
    );
    assert_eq!(measurement.payload_phase_bytes, measurement.end_bytes);

    // Unsigned inspection releases the raw manifest buffer before payload verification as well.
    let (unsigned_archive, _, unsigned_signed_message_len, unsigned_first_payload_block) =
        large_manifest_archive(false);
    let (unsigned_measurement, unsigned_manifest) =
        measure_streaming(&unsigned_archive, None, unsigned_first_payload_block);
    assert_eq!(unsigned_manifest.files.len(), MAX_FILES);
    assert!(
        unsigned_measurement.peak_bytes - unsigned_measurement.payload_phase_bytes
            >= unsigned_signed_message_len,
        "expected unsigned payload-phase live heap ({}) to drop by at least {} bytes from peak ({})",
        unsigned_measurement.payload_phase_bytes,
        unsigned_signed_message_len,
        unsigned_measurement.peak_bytes,
    );

    // Confirm invalid signature fails and poisons the verifier.
    let mut tampered = archive.clone();
    // Flip a byte in the signature block (immediately before first_payload_block).
    tampered[(first_payload_block - 1) * 512] ^= 1;
    let mut verifier = StreamingVerifier::new(Some(&public));
    let mut error = None;
    for chunk in tampered.as_chunks::<512>().0 {
        if let Err(err) = verifier.push(chunk) {
            error = Some(err);
            break;
        }
    }
    assert_eq!(error, Some(Error::InvalidSignature));
    assert_eq!(verifier.push(&[0; 512]), Err(Error::InvalidArchive));
}
