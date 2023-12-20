mod schemas;

use crate::schemas::{
    blockchain::{Byte32Builder, Uint32, Uint32Builder},
    cobuild::{
        Action, ActionBuilder, ActionVecBuilder, ByteVecBuilder, Message, MessageBuilder,
        OtxBuilder, SighashAllBuilder, WitnessLayoutBuilder,
    },
};
use blake2b_ref::Blake2bBuilder;
use ckb_types::{
    core::{Capacity, TransactionBuilder, TransactionView},
    packed::{
        Byte32, Bytes, CellDep, CellDepBuilder, CellInput, CellInputBuilder, CellOutput,
        CellOutputBuilder, OutPoint, Script, ScriptBuilder,
    },
    prelude::*,
};
use log::debug;
use molecule::prelude::Byte;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn main() {
    env_logger::init();

    let seed: u64 = match std::env::var("SEED") {
        Ok(val) => str::parse(&val).expect("parsing number"),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    };
    println!("Seed: {}", seed);

    let mut rng = StdRng::seed_from_u64(seed);

    // SighashAll tx with 2 inputs, 3 outputs, 5 witnesses
    // Message is kept in the first witness
    generate_sighash_all_example(&mut rng, "sighash_all1.data", 2, 3, 0, 0, 5, 0);

    // SighashAll tx with 2 inputs, 2 outputs, 2 cell deps, 1 header dep, 1 witness
    // Message is kept in the first witness
    generate_sighash_all_example(&mut rng, "sighash_all2.data", 2, 2, 2, 1, 1, 0);

    // SighashAllOnly tx with 1 input, 1 output, 3 witnesses, 1 cell dep
    generate_sighash_all_only_example(&mut rng, "sighash_all_only1.data", 1, 1, 1, 0, 3);

    // Otx with 2 inputs, 3 outputs, 1 cell deps, 4 header deps
    generate_otx_example(&mut rng, "otx1.data", 2, 3, 1, 4);

    // Otx with 2 inputs, 2 outputs, no cell & header deps
    generate_otx_example(&mut rng, "otx2.data", 2, 2, 0, 0);
}

#[allow(clippy::too_many_arguments)]
fn generate_sighash_all_example(
    rng: &mut StdRng,
    filename: &str,
    input_cells: u32,
    output_cells: u32,
    cell_deps: u32,
    header_deps: u32,
    witnesses: u32,
    message_witness_index: u32,
) {
    assert!(message_witness_index < witnesses);

    let message = new_message(rng);
    let sighash_all = SighashAllBuilder::default()
        .message(message.clone())
        .build();
    let witness_layout = WitnessLayoutBuilder::default().set(sighash_all).build();

    let mut builder = TransactionBuilder::default();

    for _ in 0..input_cells {
        builder = builder.input(new_input(rng));
    }
    for _ in 0..output_cells {
        let (output, data) = new_output(rng);
        builder = builder.output(output).output_data(data);
    }
    for _ in 0..cell_deps {
        builder = builder.cell_dep(new_cell_dep(rng));
    }
    for _ in 0..header_deps {
        builder = builder.header_dep(new_header_dep(rng));
    }
    for i in 0..witnesses {
        if i == message_witness_index {
            builder = builder.witness(witness_layout.as_bytes().pack());
        } else {
            builder = builder.witness(new_witness(rng));
        }
    }

    let tx = builder.build();

    std::fs::write(filename, tx.data().as_slice()).expect("write");

    let signing_message_hash = build_sighash_all_signing_hash(Some(&message), &tx);

    println!("Sighash all example written to {}", filename);
    println!("  signing message hash: {:#x}", signing_message_hash);
    println!("  Message is kept in witness #{}", message_witness_index);
}

#[allow(clippy::too_many_arguments)]
fn generate_sighash_all_only_example(
    rng: &mut StdRng,
    filename: &str,
    input_cells: u32,
    output_cells: u32,
    cell_deps: u32,
    header_deps: u32,
    witnesses: u32,
) {
    let mut builder = TransactionBuilder::default();

    for _ in 0..input_cells {
        builder = builder.input(new_input(rng));
    }
    for _ in 0..output_cells {
        let (output, data) = new_output(rng);
        builder = builder.output(output).output_data(data);
    }
    for _ in 0..cell_deps {
        builder = builder.cell_dep(new_cell_dep(rng));
    }
    for _ in 0..header_deps {
        builder = builder.header_dep(new_header_dep(rng));
    }
    for _ in 0..witnesses {
        builder = builder.witness(new_witness(rng));
    }

    let tx = builder.build();

    std::fs::write(filename, tx.data().as_slice()).expect("write");

    let signing_message_hash = build_sighash_all_signing_hash(None, &tx);

    println!(
        "Sighash all only example(i.e., tx without Message) written to {}",
        filename
    );
    println!("  signing message hash: {:#x}", signing_message_hash);
}

fn generate_otx_example(
    rng: &mut StdRng,
    filename: &str,
    input_cells: u32,
    output_cells: u32,
    cell_deps: u32,
    header_deps: u32,
) {
    let message = new_message(rng);
    let otx = OtxBuilder::default()
        .input_cells(u32_to_uint32(input_cells))
        .output_cells(u32_to_uint32(output_cells))
        .cell_deps(u32_to_uint32(cell_deps))
        .header_deps(u32_to_uint32(header_deps))
        .message(message.clone())
        .build();
    let witness_layout = WitnessLayoutBuilder::default().set(otx).build();

    let mut builder = TransactionBuilder::default().witness(witness_layout.as_bytes().pack());

    for _ in 0..input_cells {
        builder = builder.input(new_input(rng));
    }
    for _ in 0..output_cells {
        let (output, data) = new_output(rng);
        builder = builder.output(output).output_data(data);
    }
    for _ in 0..cell_deps {
        builder = builder.cell_dep(new_cell_dep(rng));
    }
    for _ in 0..header_deps {
        builder = builder.header_dep(new_header_dep(rng));
    }

    let tx = builder.build();

    std::fs::write(filename, tx.data().as_slice()).expect("write");

    let signing_message_hash = build_otx_signing_hash(&message, &tx);

    println!("Otx example written to {}", filename);
    println!("  signing message hash: {:#x}", signing_message_hash);
    println!("  Message is kept in witness #0");
}

fn new_message(rng: &mut StdRng) -> Message {
    let action_count = rng.gen_range(0..10);

    let actions: Vec<Action> = (0..action_count)
        .map(|_i| {
            let mut script_info_hash = [0u8; 32];
            rng.fill(&mut script_info_hash);
            let mut data = [Byte::new(0); 32];
            for i in 0..32 {
                data[i] = Byte::new(script_info_hash[i]);
            }
            let script_info_hash = Byte32Builder::default().set(data).build();

            let mut script_hash = [0u8; 32];
            rng.fill(&mut script_hash);
            let mut data = [Byte::new(0); 32];
            for i in 0..32 {
                data[i] = Byte::new(script_hash[i]);
            }
            let script_hash = Byte32Builder::default().set(data).build();

            let data_len = rng.gen_range(1..1000);
            let mut data = vec![0u8; data_len];
            rng.fill(&mut data[..]);
            let data = ByteVecBuilder::default()
                .extend(data.into_iter().map(|b| Byte::new(b)))
                .build();

            ActionBuilder::default()
                .script_info_hash(script_info_hash)
                .script_hash(script_hash)
                .data(data)
                .build()
        })
        .collect();

    let action_vec = ActionVecBuilder::default().extend(actions).build();

    MessageBuilder::default().actions(action_vec).build()
}

fn new_out_point(rng: &mut StdRng) -> OutPoint {
    let mut tx_hash = [0u8; 32];
    rng.fill(&mut tx_hash);
    let tx_hash = tx_hash.pack();

    OutPoint::new(tx_hash, rng.gen())
}

fn new_input(rng: &mut StdRng) -> CellInput {
    CellInputBuilder::default()
        .previous_output(new_out_point(rng))
        .since(rng.gen::<u64>().pack())
        .build()
}

fn new_script(rng: &mut StdRng) -> Script {
    let mut code_hash = [0u8; 32];
    rng.fill(&mut code_hash);
    let code_hash = code_hash.pack();

    let hash_type = rng.gen_range(0..3);

    let args_len = rng.gen_range(0..100);
    let mut args = vec![0; args_len];
    rng.fill(&mut args[..]);
    let args = args.pack();

    ScriptBuilder::default()
        .code_hash(code_hash)
        .hash_type(hash_type.into())
        .args(args)
        .build()
}

fn new_output(rng: &mut StdRng) -> (CellOutput, Bytes) {
    let data_len = rng.gen_range(0..1000);
    let cell_ckbytes = data_len + rng.gen_range(400..10000);
    let has_type = rng.gen_bool(0.5);

    let mut data = vec![0; data_len];
    rng.fill(&mut data[..]);
    let data = data.pack();

    let cell_output = CellOutputBuilder::default()
        .capacity(Capacity::bytes(cell_ckbytes).expect("capacity").pack())
        .lock(new_script(rng))
        .type_(
            (if has_type {
                Some(new_script(rng))
            } else {
                None
            })
            .pack(),
        )
        .build();

    (cell_output, data)
}

fn new_witness(rng: &mut StdRng) -> Bytes {
    let data_len = rng.gen_range(100..1000);
    let mut data = vec![0; data_len];
    rng.fill(&mut data[..]);
    data.pack()
}

fn new_cell_dep(rng: &mut StdRng) -> CellDep {
    CellDepBuilder::default()
        .out_point(new_out_point(rng))
        .dep_type(rng.gen_range(0..2).into())
        .build()
}

fn new_header_dep(rng: &mut StdRng) -> Byte32 {
    let mut header = [0u8; 32];
    rng.fill(&mut header);
    header.pack()
}

fn build_otx_signing_hash(message: &Message, tx: &TransactionView) -> Byte32 {
    debug!(
        "Building Otx signing hash for tx with {} inputs, {} outputs, {} cell deps, {} header deps",
        tx.inputs().len(),
        tx.outputs().len(),
        tx.cell_deps().len(),
        tx.header_deps().len(),
    );

    let mut blake2b = Blake2bBuilder::new(32)
        .personal(b"ckb-tcob-otxhash")
        .build();

    blake2b.update(message.as_slice());

    blake2b.update(&(tx.inputs().len() as u64).to_le_bytes());
    for input in tx.inputs().into_iter() {
        blake2b.update(input.as_slice());
    }

    blake2b.update(&(tx.outputs().len() as u64).to_le_bytes());
    for (output, data) in tx.outputs_with_data_iter() {
        blake2b.update(output.as_slice());
        blake2b.update(&(data.len() as u64).to_le_bytes());
        blake2b.update(&data);
    }

    blake2b.update(&(tx.cell_deps().len() as u64).to_le_bytes());
    for cell_dep in tx.cell_deps_iter() {
        blake2b.update(cell_dep.as_slice());
    }

    blake2b.update(&(tx.header_deps().len() as u64).to_le_bytes());
    for header_dep in tx.header_deps_iter() {
        blake2b.update(header_dep.as_slice());
    }

    let mut output = [0u8; 32];
    blake2b.finalize(&mut output);
    output.pack()
}

fn build_sighash_all_signing_hash(message: Option<&Message>, tx: &TransactionView) -> Byte32 {
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(if message.is_some() {
            b"ckb-tcob-sighash"
        } else {
            b"ckb-tcob-sgohash"
        })
        .build();

    if let Some(message) = message {
        blake2b.update(message.as_slice());
    }

    debug!(
        "Building SighashAll signing hash for tx with {} inputs, {} outputs, {} witnesses",
        tx.inputs().len(),
        tx.outputs().len(),
        tx.witnesses().len()
    );

    debug!("Hashing tx hash: {:x}", tx.hash());
    blake2b.update(&tx.hash().raw_data());

    let inputs_len = tx.inputs().len();
    for (i, witness) in tx.witnesses().into_iter().enumerate().skip(inputs_len) {
        debug!("Hashing witness at index {}, len: {}", i, witness.len());
        blake2b.update(&(witness.len() as u64).to_le_bytes());
        blake2b.update(&witness.raw_data());
    }

    let mut output = [0u8; 32];
    blake2b.finalize(&mut output);
    output.pack()
}

fn u32_to_uint32(v: u32) -> Uint32 {
    let data = v.to_le_bytes();
    Uint32Builder::default()
        .nth0(Byte::new(data[0]))
        .nth1(Byte::new(data[1]))
        .nth2(Byte::new(data[2]))
        .nth3(Byte::new(data[3]))
        .build()
}
