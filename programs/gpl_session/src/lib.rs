#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::system_program;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

#[cfg(feature = "no-entrypoint")]
pub use session_keys_macros::*;

declare_id!("KeyspM2ssCJbqUhQ4k7sveSiY4WjnYsrXkC8oDbwde5");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "session_keys",
    project_url: "https://magicblock.gg",
    contacts: "email:dev@magicblock.gg,twitter:@magicblock",
    policy: "",
    preferred_languages: "en",
    source_code: "https://github.com/magicblock-labs"
}

#[program]
pub mod gpl_session {
    use super::*;

    // create a session token
    pub fn create_session(
        ctx: Context<CreateSessionToken>,
        top_up: Option<bool>,
        valid_until: Option<i64>,
        lamports: Option<u64>,
    ) -> Result<()> {
        let (top_up, valid_until) = process_session_params(top_up, valid_until)?;
        create_session_token_handler(ctx, top_up, valid_until, lamports)
    }

    pub fn create_session_with_payer(
        ctx: Context<CreateSessionTokenWithPayer>,
        top_up: Option<bool>,
        valid_until: Option<i64>,
        lamports: Option<u64>,
    ) -> Result<()> {
        let (top_up, valid_until) = process_session_params(top_up, valid_until)?;
        create_session_token_with_payer_handler(ctx, top_up, valid_until, lamports)
    }
    // revoke a session token
    pub fn revoke_session(ctx: Context<RevokeSessionToken>) -> Result<()> {
        revoke_session_token_handler(ctx)
    }

    // V2 instructions
    //
    // Added the V2 instructions to support the new session token format.
    // The new format allows session to be created with a payer which on revoking
    // would send the lamports back to the payer.
    pub fn create_session_v2(
        ctx: Context<CreateSessionTokenV2>,
        top_up: Option<bool>,
        valid_until: Option<i64>,
        lamports: Option<u64>,
    ) -> Result<()> {
        let (top_up, valid_until) = process_session_params(top_up, valid_until)?;
        create_session_token_handler_v2(ctx, top_up, valid_until, lamports)
    }

    pub fn revoke_session_v2(ctx: Context<RevokeSessionTokenV2>) -> Result<()> {
        revoke_session_token_handler_v2(ctx)
    }
}

fn process_session_params(top_up: Option<bool>, valid_until: Option<i64>) -> Result<(bool, i64)> {
    let top_up = top_up.unwrap_or(false);
    let valid_until = valid_until.unwrap_or(Clock::get()?.unix_timestamp + 60 * 60);
    Ok((top_up, valid_until))
}

// Create a SessionToken account
#[derive(Accounts)]
pub struct CreateSessionToken<'info> {
    #[account(
        init,
        seeds = [
            SessionToken::SEED_PREFIX.as_bytes(),
            target_program.key().as_ref(),
            session_signer.key().as_ref(),
            authority.key().as_ref()
        ],
        bump,
        payer = authority,
        space = SessionToken::LEN
    )]
    pub session_token: Account<'info, SessionToken>,

    #[account(mut)]
    pub session_signer: Signer<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK the target program is actually a program.
    #[account(executable)]
    pub target_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

struct CreateSessionTokenParams {
    authority: Pubkey,
    target_program: Pubkey,
    session_signer: Pubkey,
    top_up: bool,
    valid_until: i64,
    lamports: Option<u64>,
}

fn create_session_token_internal<'info>(
    session_token: &mut Account<'info, SessionToken>,
    params: CreateSessionTokenParams,
    system_program: AccountInfo<'info>,
    payer: AccountInfo<'info>,
    session_signer_account: AccountInfo<'info>,
) -> Result<()> {
    let authority = params.authority;
    let target_program = params.target_program;
    let session_signer = params.session_signer;
    let top_up = params.top_up;
    let valid_until = params.valid_until;
    let lamports = params.lamports;
    // Valid until can't be greater than a week
    require!(
        valid_until <= Clock::get()?.unix_timestamp + (60 * 60 * 24 * 7),
        SessionError::ValidityTooLong
    );

    session_token.set_inner(SessionToken {
        authority,
        target_program,
        session_signer,
        valid_until,
    });

    // Top up the session signer account with some lamports to pay for the transaction fees
    if top_up {
        system_program::transfer(
            CpiContext::new(
                system_program,
                system_program::Transfer {
                    from: payer,
                    to: session_signer_account,
                },
            ),
            lamports.unwrap_or(LAMPORTS_PER_SOL / 100),
        )?;
    }

    Ok(())
}

// Handler to create a session token account
pub fn create_session_token_handler(
    ctx: Context<CreateSessionToken>,
    top_up: bool,
    valid_until: i64,
    lamports: Option<u64>,
) -> Result<()> {
    create_session_token_internal(
        &mut ctx.accounts.session_token,
        CreateSessionTokenParams {
            authority: ctx.accounts.authority.key(),
            target_program: ctx.accounts.target_program.key(),
            session_signer: ctx.accounts.session_signer.key(),
            top_up,
            valid_until,
            lamports,
        },
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.session_signer.to_account_info(),
    )
}

// Create a SessionToken account
#[derive(Accounts)]
pub struct CreateSessionTokenWithPayer<'info> {
    #[account(
        init,
        seeds = [
            SessionToken::SEED_PREFIX.as_bytes(),
            target_program.key().as_ref(),
            session_signer.key().as_ref(),
            authority.key().as_ref()
        ],
        bump,
        payer = payer,
        space = SessionToken::LEN
    )]
    pub session_token: Account<'info, SessionToken>,

    #[account(mut)]
    pub session_signer: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub authority: Signer<'info>,

    /// CHECK the target program is actually a program.
    #[account(executable)]
    pub target_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

// Handler to create a session token account
pub fn create_session_token_with_payer_handler(
    ctx: Context<CreateSessionTokenWithPayer>,
    top_up: bool,
    valid_until: i64,
    lamports: Option<u64>,
) -> Result<()> {
    create_session_token_internal(
        &mut ctx.accounts.session_token,
        CreateSessionTokenParams {
            authority: ctx.accounts.authority.key(),
            target_program: ctx.accounts.target_program.key(),
            session_signer: ctx.accounts.session_signer.key(),
            top_up,
            valid_until,
            lamports,
        },
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.payer.to_account_info(),
        ctx.accounts.session_signer.to_account_info(),
    )
}

// Revoke a session token
// We allow *anyone* to revoke a session token. This is because the session token is designed to
// expire on it's own after a certain amount of time. However, if the session token is compromised
// anyone can revoke it immediately.
//
// One attack vector here to consider, however is that a malicious actor could enumerate all the tokens
// created using the program and revoke them all or keep revoking them as they are created. It is a
// nuisance but not a security risk. We can easily address this by whitelisting a revoker.
#[derive(Accounts)]
pub struct RevokeSessionToken<'info> {
    #[account(
        mut,
        seeds = [
            SessionToken::SEED_PREFIX.as_bytes(),
            session_token.target_program.key().as_ref(),
            session_token.session_signer.key().as_ref(),
            session_token.authority.key().as_ref()
        ],
        bump,
        has_one = authority,
        close = authority,
    )]
    pub session_token: Account<'info, SessionToken>,

    #[account(mut)]
    // Only the token authority can reclaim the rent
    pub authority: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

// Handler to revoke a session token
pub fn revoke_session_token_handler(_: Context<RevokeSessionToken>) -> Result<()> {
    Ok(())
}

// V2 Accounts and Handlers

// Create a SessionTokenV2 account
#[derive(Accounts)]
pub struct CreateSessionTokenV2<'info> {
    #[account(
        init,
        seeds = [
            SessionTokenV2::SEED_PREFIX.as_bytes(),
            target_program.key().as_ref(),
            session_signer.key().as_ref(),
            authority.key().as_ref()
        ],
        bump,
        payer = fee_payer,
        space = SessionTokenV2::LEN
    )]
    pub session_token: Account<'info, SessionTokenV2>,

    #[account(mut)]
    pub session_signer: Signer<'info>,
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    pub authority: Signer<'info>,

    /// CHECK the target program is actually a program.
    #[account(executable)]
    pub target_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

struct CreateSessionTokenV2Params {
    authority: Pubkey,
    target_program: Pubkey,
    session_signer: Pubkey,
    fee_payer: Pubkey,
    top_up: bool,
    valid_until: i64,
    lamports: Option<u64>,
}

fn create_session_token_v2_internal<'info>(
    session_token: &mut Account<'info, SessionTokenV2>,
    params: CreateSessionTokenV2Params,
    system_program: AccountInfo<'info>,
    payer: AccountInfo<'info>,
    session_signer_account: AccountInfo<'info>,
) -> Result<()> {
    let authority = params.authority;
    let target_program = params.target_program;
    let session_signer = params.session_signer;
    let fee_payer = params.fee_payer;
    let top_up = params.top_up;
    let valid_until = params.valid_until;
    let lamports = params.lamports;
    // Valid until can't be greater than a week
    require!(
        valid_until <= Clock::get()?.unix_timestamp + (60 * 60 * 24 * 7),
        SessionError::ValidityTooLong
    );

    session_token.set_inner(SessionTokenV2 {
        authority,
        target_program,
        session_signer,
        fee_payer,
        valid_until,
    });

    // Top up the session signer account with some lamports to pay for the transaction fees
    if top_up {
        system_program::transfer(
            CpiContext::new(
                system_program,
                system_program::Transfer {
                    from: payer,
                    to: session_signer_account,
                },
            ),
            lamports.unwrap_or(LAMPORTS_PER_SOL / 100),
        )?;
    }

    Ok(())
}

// Handler to create a session token v2 account
pub fn create_session_token_handler_v2(
    ctx: Context<CreateSessionTokenV2>,
    top_up: bool,
    valid_until: i64,
    lamports: Option<u64>,
) -> Result<()> {
    create_session_token_v2_internal(
        &mut ctx.accounts.session_token,
        CreateSessionTokenV2Params {
            authority: ctx.accounts.authority.key(),
            target_program: ctx.accounts.target_program.key(),
            session_signer: ctx.accounts.session_signer.key(),
            fee_payer: ctx.accounts.fee_payer.key(),
            top_up,
            valid_until,
            lamports,
        },
        ctx.accounts.system_program.to_account_info(),
        ctx.accounts.fee_payer.to_account_info(),
        ctx.accounts.session_signer.to_account_info(),
    )
}

// Revoke a session token V2
//
// Anybody can revoke session but only the fee payer will receive the lamports back.
#[derive(Accounts)]
pub struct RevokeSessionTokenV2<'info> {
    #[account(
        mut,
        seeds = [
            SessionTokenV2::SEED_PREFIX.as_bytes(),
            session_token.target_program.key().as_ref(),
            session_token.session_signer.key().as_ref(),
            session_token.authority.key().as_ref()
        ],
        bump,
        has_one = fee_payer,
        has_one = authority,
        close = fee_payer,
    )]
    pub session_token: Account<'info, SessionTokenV2>,

    #[account(mut)]
    // Lamports are sent back to the fee payer
    pub fee_payer: SystemAccount<'info>,

    // Requires to be a signer if session is still active
    pub authority: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

// Handler to revoke a session token V2
pub fn revoke_session_token_handler_v2(ctx: Context<RevokeSessionTokenV2>) -> Result<()> {
    // If the session is still active, the authority must be a signer
    if !ctx.accounts.session_token.is_expired()? {
        require!(
            ctx.accounts.authority.is_signer,
            SessionError::InvalidAuthority
        );
    }
    Ok(())
}

pub struct ValidityChecker<'info> {
    pub session_token: Account<'info, SessionToken>,
    pub session_signer: Signer<'info>,
    pub authority: Pubkey,
    pub target_program: Pubkey,
}

pub struct ValidityCheckerV2<'info> {
    pub session_token: Account<'info, SessionTokenV2>,
    pub session_signer: Signer<'info>,
    pub authority: Pubkey,
    pub target_program: Pubkey,
}

// SessionToken Account
#[account]
#[derive(Copy)]
pub struct SessionToken {
    pub authority: Pubkey,
    pub target_program: Pubkey,
    pub session_signer: Pubkey,
    pub valid_until: i64,
}

#[account]
#[derive(Copy)]
pub struct SessionTokenV2 {
    pub authority: Pubkey,
    pub target_program: Pubkey,
    pub session_signer: Pubkey,
    // account that paid for initialization and receives lamports back on revoking
    pub fee_payer: Pubkey,
    pub valid_until: i64,
}

impl SessionToken {
    pub const LEN: usize = 8 + std::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static str = "session_token";

    fn is_expired(&self) -> Result<bool> {
        let now = Clock::get()?.unix_timestamp;
        Ok(now < self.valid_until)
    }

    // validate the token
    pub fn validate(&self, ctx: ValidityChecker) -> Result<bool> {
        let target_program = ctx.target_program;
        let session_signer = ctx.session_signer.key();
        let authority = ctx.authority.key();

        // Check the PDA seeds
        let seeds = &[
            SessionToken::SEED_PREFIX.as_bytes(),
            target_program.as_ref(),
            session_signer.as_ref(),
            authority.as_ref(),
        ];

        let (pda, _) = Pubkey::find_program_address(seeds, &crate::id());

        require_eq!(pda, ctx.session_token.key(), SessionError::InvalidToken);

        // Check if the token has expired
        self.is_expired()
    }
}

impl SessionTokenV2 {
    pub const LEN: usize = 8 + std::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static str = "session_token_v2";
}

impl SessionTokenV2 {
    pub fn is_expired(&self) -> Result<bool> {
        let now = Clock::get()?.unix_timestamp;
        Ok(now > self.valid_until)
    }

    // validate the token
    pub fn validate(&self, ctx: ValidityCheckerV2) -> Result<bool> {
        let target_program = ctx.target_program;
        let session_signer = ctx.session_signer.key();
        let authority = ctx.authority.key();

        // Check the PDA seeds
        let seeds = &[
            SessionTokenV2::SEED_PREFIX.as_bytes(),
            target_program.as_ref(),
            session_signer.as_ref(),
            authority.as_ref(),
        ];

        let (pda, _) = Pubkey::find_program_address(seeds, &crate::id());

        require_eq!(pda, ctx.session_token.key(), SessionError::InvalidToken);

        // Check if the token has expired
        self.is_expired()
    }
}

pub trait Session<'info> {
    fn session_token(&self) -> Option<Account<'info, SessionToken>>;
    fn session_signer(&self) -> Signer<'info>;
    fn session_authority(&self) -> Pubkey;
    fn target_program(&self) -> Pubkey;

    fn is_valid(&self) -> Result<bool> {
        let session_token = self.session_token().ok_or(SessionError::NoToken)?;
        let validity_ctx = ValidityChecker {
            session_token: session_token.clone(),
            session_signer: self.session_signer(),
            authority: self.session_authority(),
            target_program: self.target_program(),
        };
        // Check if the token is valid
        session_token.validate(validity_ctx)
    }
}

pub trait SessionV2<'info> {
    fn session_token(&self) -> Option<Account<'info, SessionTokenV2>>;
    fn session_signer(&self) -> Signer<'info>;
    fn session_authority(&self) -> Pubkey;
    fn target_program(&self) -> Pubkey;

    fn is_valid(&self) -> Result<bool> {
        let session_token = self.session_token().ok_or(SessionError::NoToken)?;
        let validity_ctx = ValidityCheckerV2 {
            session_token: session_token.clone(),
            session_signer: self.session_signer(),
            authority: self.session_authority(),
            target_program: self.target_program(),
        };
        // Check if the token is valid
        session_token.validate(validity_ctx)
    }
}

#[error_code]
pub enum SessionError {
    #[msg("Requested validity is too long")]
    ValidityTooLong,
    #[msg("Invalid session token")]
    InvalidToken,
    #[msg("No session token provided")]
    NoToken,
    #[msg("Invalid authority")]
    InvalidAuthority,
}
