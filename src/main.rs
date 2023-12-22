mod schemas;

use crate::schemas::{
    blockchain::{
        self, Byte32Builder, BytesVecBuilder, CellOutputVecBuilder, Uint32, Uint32Builder,
    },
    cobuild::{
        Action, ActionBuilder, ActionVecBuilder, BuildingPacket, BuildingPacketBuilder,
        BuildingPacketUnion, BuildingPacketV1Builder, ByteVecBuilder, Message, MessageBuilder,
        OtxBuilder, ResolvedInputsBuilder, SighashAllBuilder, SighashAllOnlyBuilder,
        WitnessLayoutBuilder,
    },
};
use blake2b_ref::Blake2bBuilder;
// TODO: Remove ckb_types here for a single unified use of blockchain types
use ckb_types::{
    core::TransactionBuilder,
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

    let mut builder = TransactionBuilder::default();
    let mut cell_input_builder = CellOutputVecBuilder::default();
    let mut cell_input_data_builder = BytesVecBuilder::default();

    for _ in 0..input_cells {
        builder = builder.input(new_input(rng));

        let (output, data) = new_output(rng);
        cell_input_builder =
            cell_input_builder.push(blockchain::CellOutput::from_slice(output.as_slice()).unwrap());
        cell_input_data_builder =
            cell_input_data_builder.push(blockchain::Bytes::from_slice(data.as_slice()).unwrap());
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
            let a = WitnessLayoutBuilder::default()
                .set(SighashAllBuilder::default().build())
                .build();
            builder = builder.witness(a.as_bytes().pack());
        } else if i < input_cells {
            let o = WitnessLayoutBuilder::default()
                .set(SighashAllOnlyBuilder::default().build())
                .build();
            builder = builder.witness(o.as_bytes().pack());
        } else {
            builder = builder.witness(new_witness(rng));
        }
    }

    let tx = builder.build();

    let resolved_inputs = ResolvedInputsBuilder::default()
        .outputs(cell_input_builder.build())
        .outputs_data(cell_input_data_builder.build())
        .build();

    let packet = BuildingPacketBuilder::default()
        .set(
            BuildingPacketV1Builder::default()
                .message(message)
                .payload(blockchain::Transaction::from_slice(tx.data().as_slice()).unwrap())
                .resolved_inputs(resolved_inputs)
                .build(),
        )
        .build();

    std::fs::write(filename, packet.as_slice()).expect("write");

    let signing_message_hash = build_sighash_all_signing_hash(&packet, false);

    println!(
        "Sighash all example written to {} as BuildingPacket",
        filename
    );
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
    let mut cell_input_builder = CellOutputVecBuilder::default();
    let mut cell_input_data_builder = BytesVecBuilder::default();

    for _ in 0..input_cells {
        builder = builder.input(new_input(rng));

        let (output, data) = new_output(rng);
        cell_input_builder =
            cell_input_builder.push(blockchain::CellOutput::from_slice(output.as_slice()).unwrap());
        cell_input_data_builder =
            cell_input_data_builder.push(blockchain::Bytes::from_slice(data.as_slice()).unwrap());
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
        if i < input_cells {
            let o = WitnessLayoutBuilder::default()
                .set(SighashAllOnlyBuilder::default().build())
                .build();
            builder = builder.witness(o.as_bytes().pack());
        } else {
            builder = builder.witness(new_witness(rng));
        }
    }

    let tx = builder.build();

    let resolved_inputs = ResolvedInputsBuilder::default()
        .outputs(cell_input_builder.build())
        .outputs_data(cell_input_data_builder.build())
        .build();

    let packet = BuildingPacketBuilder::default()
        .set(
            BuildingPacketV1Builder::default()
                .payload(blockchain::Transaction::from_slice(tx.data().as_slice()).unwrap())
                .resolved_inputs(resolved_inputs)
                .build(),
        )
        .build();

    std::fs::write(filename, packet.as_slice()).expect("write");

    let signing_message_hash = build_sighash_all_signing_hash(&packet, true);

    println!(
        "Sighash all only example(i.e., tx without Message) written to {} as BuildingPacket",
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
    let mut cell_input_builder = CellOutputVecBuilder::default();
    let mut cell_input_data_builder = BytesVecBuilder::default();

    for _ in 0..input_cells {
        builder = builder.input(new_input(rng));

        let (output, data) = new_output(rng);
        cell_input_builder =
            cell_input_builder.push(blockchain::CellOutput::from_slice(output.as_slice()).unwrap());
        cell_input_data_builder =
            cell_input_data_builder.push(blockchain::Bytes::from_slice(data.as_slice()).unwrap());
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

    let resolved_inputs = ResolvedInputsBuilder::default()
        .outputs(cell_input_builder.build())
        .outputs_data(cell_input_data_builder.build())
        .build();

    let packet = BuildingPacketBuilder::default()
        .set(
            BuildingPacketV1Builder::default()
                .message(message)
                .payload(blockchain::Transaction::from_slice(tx.data().as_slice()).unwrap())
                .resolved_inputs(resolved_inputs)
                .build(),
        )
        .build();

    std::fs::write(filename, packet.as_slice()).expect("write");

    let signing_message_hash = build_otx_signing_hash(&packet);

    println!("Otx example written to {} as BuildingPacket", filename);
    println!("  signing message hash: {:#x}", signing_message_hash);
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
                .extend(data.into_iter().map(Byte::new))
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
        .capacity((cell_ckbytes as u64 * 100_000_000).pack())
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

fn build_otx_signing_hash(packet: &BuildingPacket) -> Byte32 {
    let BuildingPacketUnion::BuildingPacketV1(v1_packet) = packet.to_enum();
    let tx = v1_packet.payload();

    debug!(
        "Building Otx signing hash for tx with {} inputs, {} outputs, {} cell deps, {} header deps",
        tx.raw().inputs().len(),
        tx.raw().outputs().len(),
        tx.raw().cell_deps().len(),
        tx.raw().header_deps().len(),
    );

    let mut blake2b = Blake2bBuilder::new(32)
        .personal(b"ckb-tcob-otxhash")
        .build();

    blake2b.update(v1_packet.message().as_slice());

    blake2b.update(&(tx.raw().inputs().len() as u32).to_le_bytes());
    for (i, input) in tx.raw().inputs().into_iter().enumerate() {
        blake2b.update(input.as_slice());
        blake2b.update(
            v1_packet
                .resolved_inputs()
                .outputs()
                .get(i)
                .expect("indexing input")
                .as_slice(),
        );
        let data = v1_packet
            .resolved_inputs()
            .outputs_data()
            .get(i)
            .expect("indexing input data");
        blake2b.update(&(data.len() as u32).to_le_bytes());
        blake2b.update(&data.raw_data());
    }

    blake2b.update(&(tx.raw().outputs().len() as u32).to_le_bytes());
    for (i, output) in tx.raw().outputs().into_iter().enumerate() {
        let data = tx.raw().outputs_data().get(i).expect("indexing cell data");
        blake2b.update(output.as_slice());
        blake2b.update(&(data.len() as u32).to_le_bytes());
        blake2b.update(&data.raw_data());
    }

    blake2b.update(&(tx.raw().cell_deps().len() as u32).to_le_bytes());
    for cell_dep in tx.raw().cell_deps().into_iter() {
        blake2b.update(cell_dep.as_slice());
    }

    blake2b.update(&(tx.raw().header_deps().len() as u32).to_le_bytes());
    for header_dep in tx.raw().header_deps().into_iter() {
        blake2b.update(header_dep.as_slice());
    }

    let mut output = [0u8; 32];
    blake2b.finalize(&mut output);
    output.pack()
}

fn build_sighash_all_signing_hash(packet: &BuildingPacket, sighash_all_only: bool) -> Byte32 {
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(if !sighash_all_only {
            b"ckb-tcob-sighash"
        } else {
            b"ckb-tcob-sgohash"
        })
        .build();

    let BuildingPacketUnion::BuildingPacketV1(v1_packet) = packet.to_enum();
    let tx = v1_packet.payload();

    if !sighash_all_only {
        blake2b.update(v1_packet.message().as_slice());
    }

    debug!(
        "Building SighashAll signing hash for tx with {} inputs, {} outputs, {} witnesses",
        tx.raw().inputs().len(),
        tx.raw().outputs().len(),
        tx.witnesses().len()
    );

    let hash: molecule::bytes::Bytes = ckb_hash::blake2b_256(tx.raw().as_slice()).to_vec().into();
    debug!("Hashing tx hash: {:x}", hash);
    blake2b.update(&hash);

    for (i, _) in tx.raw().inputs().into_iter().enumerate() {
        let data = v1_packet
            .resolved_inputs()
            .outputs_data()
            .get(i)
            .expect("indexing input data");
        debug!(
            "Hashing input cell content at index {}, cell data len: {}",
            i,
            data.len()
        );
        blake2b.update(
            v1_packet
                .resolved_inputs()
                .outputs()
                .get(i)
                .expect("indexing input")
                .as_slice(),
        );
        blake2b.update(&(data.len() as u32).to_le_bytes());
        blake2b.update(&data.raw_data());
    }

    let inputs_len = tx.raw().inputs().len();
    for (i, witness) in tx.witnesses().into_iter().enumerate().skip(inputs_len) {
        debug!("Hashing witness at index {}, len: {}", i, witness.len());
        blake2b.update(&(witness.len() as u32).to_le_bytes());
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
