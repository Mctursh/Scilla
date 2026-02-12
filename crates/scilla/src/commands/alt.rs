use std::fmt::{Display, Formatter, Result};

use comfy_table::{Table, Cell, presets::UTF8_FULL};
use console::style;
use solana_address_lookup_table_interface::{instruction::{create_lookup_table, extend_lookup_table}, state::AddressLookupTable};
use solana_keypair::Signer;
use solana_pubkey::Pubkey;

use crate::{commands::{Command, CommandFlow, navigation::{NavigationSection, NavigationTarget}}, context::ScillaContext, misc::helpers::{build_and_send_tx, parse_addresses_string_to_pubkeys, unpack_option_to_string}, prompt::prompt_input_data, ui::show_spinner};

#[derive(Debug, Clone, Copy)]
pub enum AltCommand {
    Create,
    Extend,
    Get,
    Freeze,
    Deactivate,
    Close,
    GoBack,
}

impl AltCommand {
    pub fn spinner_msg(&self) -> &'static str {
        match self {
            AltCommand::Create => "Creating Table",
            AltCommand::Get => "Fetching Table",
            AltCommand::Extend => "Extending Table",
            AltCommand::Freeze => "Freezing Table",
            AltCommand::Deactivate => "Deactivating Table",
            AltCommand::Close => "Closing Table",
            AltCommand::GoBack => "Going Back...",
        }
    }
}

impl Display for AltCommand {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let command = match self {
            AltCommand::Create => "Create ALT",
            AltCommand::Extend => "Extend ALT",
            AltCommand::Get => "Get ALT",
            AltCommand::Freeze => "Freeze ALT",
            AltCommand::Deactivate => "Deactivate ALT",
            AltCommand::Close => "Close ALT",
            AltCommand::GoBack => "Going Back...",
        };
        write!(f, "{command}")
    }
}

// io
impl Command for AltCommand {
    async fn process_command(&self, ctx: &mut ScillaContext) -> anyhow::Result<CommandFlow> {
        ctx.get_nav_context_mut()
            .checked_push(NavigationSection::AddressLookupTable);
        match self {
            AltCommand::Create => {
                show_spinner( self.spinner_msg(), create_table(ctx)).await;
            }
            
            AltCommand::Get => {
                let pubkey: Pubkey = prompt_input_data("Enter ALT Address :");
                show_spinner( self.spinner_msg(), get_lookup_table(ctx, &pubkey)).await;
            }
            
            AltCommand::Extend => {
                let pubkey: Pubkey = prompt_input_data("Enter ALT Address :");
                let addresses_string: String = prompt_input_data("Enter addresses to add (comma-separated) :");
                show_spinner( self.spinner_msg(), extend_table(ctx, pubkey, &addresses_string)).await;
            }
            
            AltCommand::Freeze => {
                show_spinner( self.spinner_msg(), freeze_lookup_table(ctx)).await;
            }
            
            AltCommand::Deactivate => {
                show_spinner( self.spinner_msg(), deactivate_lookup_table(ctx)).await;
            }
            
            AltCommand::Close => {
                show_spinner( self.spinner_msg(), close_lookup_table(ctx)).await;
            }
            
            AltCommand::GoBack => {
                return Ok(CommandFlow::NavigateTo(NavigationTarget::PreviousSection));
            }
        }
        Ok(CommandFlow::Processed)
    }
}

async fn create_table(ctx: &ScillaContext) -> anyhow::Result<()> {
    let recent_slot = ctx.rpc().get_slot().await?;
    let (instruction, pubkey) = create_lookup_table(ctx.keypair().pubkey(), ctx.keypair().pubkey(), recent_slot);

    let signature = build_and_send_tx(ctx, &[instruction], &[ctx.keypair()]).await?;

    println!(
        "{}\n{}\n{}",
        style("Address Lookup Table created successfully!").yellow().bold(),
        style(format!("ALT Address: {pubkey}")).cyan(),
        style(format!("Signature: {signature}")).green()
    );

    Ok(())
}

async fn get_lookup_table(ctx: &ScillaContext, pubkey: &Pubkey) -> anyhow::Result<()> {
    let account = ctx.rpc().get_account(pubkey).await?;
    let alt_table_data = AddressLookupTable::deserialize(&account.data)?;

    // Metadata table
    let mut metadata_table = Table::new();
    metadata_table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Field")
                .add_attribute(comfy_table::Attribute::Bold)
                .fg(comfy_table::Color::Cyan),
            Cell::new("Value")
                .add_attribute(comfy_table::Attribute::Bold)
                .fg(comfy_table::Color::Cyan),
        ])
        .add_row(vec![Cell::new("LookUp Table Address"), Cell::new(pubkey)])
        .add_row(vec![
            Cell::new("Authority"),
            Cell::new(unpack_option_to_string(&alt_table_data.meta.authority)),
        ])
        .add_row(vec![
            Cell::new("Deactivation Slot"),
            Cell::new(format!("{}", alt_table_data.meta.deactivation_slot)),
        ])
        .add_row(vec![Cell::new("Last Extended Slot"), Cell::new(format!("{}", alt_table_data.meta.last_extended_slot))]);
    println!("{}\n{}", style("ALT METADATA").green().bold(), metadata_table);

    if !alt_table_data.addresses.is_empty() {                                                            
        let mut address_table = Table::new();
        address_table
            .load_preset(UTF8_FULL)
            .set_header(vec![
                Cell::new("Index")
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Cyan),
                Cell::new("Address")
                    .add_attribute(comfy_table::Attribute::Bold)
                    .fg(comfy_table::Color::Cyan),
            ]);
            
        for (index, address) in alt_table_data.addresses.iter().enumerate() {
            address_table.add_row(vec![
                Cell::new(index),
                Cell::new(address.to_string())  
            ]);
        }
        println!("{}\n{}", style("ADDRESS LOOKUP TABLE").green().bold(), address_table);
    } else {                                                                               
        println!("{}", style("No addresses stored in this table").yellow());                             
    }                                                                                    

    Ok(())
}

async fn freeze_lookup_table(_ctx: &ScillaContext) -> anyhow::Result<()> {
    todo!();
    // Ok(())
}

async fn deactivate_lookup_table(_ctx: &ScillaContext) -> anyhow::Result<()> {
    todo!();
    // Ok(())
}

async fn extend_table(ctx: &ScillaContext, alt_address: Pubkey, address_strings: &str) -> anyhow::Result<()> {
    let address_pubkeys: Vec<Pubkey> = parse_addresses_string_to_pubkeys(address_strings)?;
    let address_len = address_pubkeys.len();
    let instruction = extend_lookup_table(alt_address, *ctx.pubkey(), Some(*ctx.pubkey()), address_pubkeys);

    let signature = build_and_send_tx(ctx, &[instruction], &[ctx.keypair()]).await?;

    println!(
        "{}\n{}\n{}\n{}",
        style("Lookup Table extended successfully!").yellow().bold(),
        style(format!("ALT Address: {alt_address}")).cyan(),
        style(format!("Addresses Added: {}", address_len)).cyan(),
        style(format!("Signature: {signature}")).green()
    );
    Ok(())
}

async fn close_lookup_table(_ctx: &ScillaContext) -> anyhow::Result<()> {
    todo!();
    // Ok(())
}