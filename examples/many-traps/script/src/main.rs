use sp1_sdk::ProverClient;
use sp1_sdk::prelude::*;

const ELF: Elf = include_elf!("many-traps-program");

#[tokio::main]
async fn main() {
    // Setup a tracer for logging.
    sp1_sdk::utils::setup_logger();

    println!("Running many-traps example");

    // No stdin needed for this simple example
    let mut stdin = SP1Stdin::new();

    // How many traps from memory operations to trigger
    stdin.write(&1000u32);
    // How many traps from precompile operations to trigger
    stdin.write(&500u32);

    let client = ProverClient::builder().cpu().build().await;

    // Execute the program first
    println!("Executing program...");
    let (public_output, execution_report) = client.execute(ELF, stdin.clone()).await.unwrap();

    println!("Program executed successfully!");
    println!("Public output: {:?}", public_output);

    // Print execution statistics
    println!(
        "Executed program with {} total instructions",
        execution_report.total_instruction_count()
    );
    println!("Total syscalls: {}", execution_report.total_syscall_count());

    // Print syscall breakdown to see mprotect calls
    println!("Syscall breakdown:");
    for (syscall_code, count) in execution_report.syscall_counts.iter() {
        if *count > 0 {
            println!("  {:?}: {}", syscall_code, count);
        }
    }
}
