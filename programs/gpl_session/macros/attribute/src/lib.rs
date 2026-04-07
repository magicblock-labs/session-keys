use proc_macro::TokenStream;
use quote::{quote, ToTokens};

use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Data, DeriveInput, Fields, GenericArgument, PathArguments, Token, Type,
    TypePath,
};

struct SessionArgs {
    signer: syn::ExprAssign,
    authority: syn::ExprAssign,
}

impl Parse for SessionArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let signer = input.parse()?;

        input.parse::<Token![,]>()?;

        let authority = input.parse()?;
        Ok(SessionArgs { signer, authority })
    }
}

fn is_session(attr: &syn::Attribute) -> bool {
    attr.path.is_ident("session")
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum SessionTokenType {
    V1,
    V2,
}

/// Result of parsing the session_token field type.
struct SessionTokenInfo {
    token_type: SessionTokenType,
    /// The lifetime from Account<'info, ...> — used in generated impl.
    lifetime: syn::Lifetime,
}

fn get_session_token_info(ty: &Type) -> Option<SessionTokenInfo> {
    let Type::Path(TypePath { path, .. }) = ty else {
        return None;
    };
    let Some(seg) = path.segments.last() else {
        return None;
    };
    if seg.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(ref opt_args) = seg.arguments else {
        return None;
    };
    let Some(GenericArgument::Type(Type::Path(TypePath {
        path: acct_path, ..
    }))) = opt_args.args.first()
    else {
        return None;
    };
    let Some(acct_seg) = acct_path.segments.last() else {
        return None;
    };
    if acct_seg.ident != "Account" {
        return None;
    }
    let PathArguments::AngleBracketed(ref acct_args) = acct_seg.arguments else {
        return None;
    };
    let mut args = acct_args.args.iter();
    let Some(GenericArgument::Lifetime(lifetime)) = args.next() else {
        return None;
    };
    let lifetime = lifetime.clone();
    let Some(GenericArgument::Type(Type::Path(TypePath { path: st_path, .. }))) = args.next()
    else {
        return None;
    };

    if let Some(st_seg) = st_path.segments.last() {
        if st_seg.ident == "SessionToken" {
            return Some(SessionTokenInfo { token_type: SessionTokenType::V1, lifetime });
        } else if st_seg.ident == "SessionTokenV2" {
            return Some(SessionTokenInfo { token_type: SessionTokenType::V2, lifetime });
        }
    }
    None
}

/// Core derive implementation that supports both V1 (`SessionToken`) and V2 (`SessionTokenV2`).
/// Auto-detects which variant to use based on the `session_token` field type.
/// If `expected` is `Some`, validates that the detected type matches.
fn derive_impl(input: TokenStream, expected: Option<SessionTokenType>) -> TokenStream {
    let input_parsed = parse_macro_input!(input as DeriveInput);

    let fields = match input_parsed.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => fields,
            _ => panic!("Session trait can only be derived for structs with named fields"),
        },
        _ => panic!("Session trait can only be derived for structs"),
    };

    // Ensure that the struct has a session_token field
    let session_token_field = fields
        .named
        .iter()
        .find(|field| field.ident.as_ref().unwrap().to_string() == "session_token")
        .expect("Session trait can only be derived for structs with a session_token field");

    let session_token_type = &session_token_field.ty;
    let info = get_session_token_info(session_token_type)
        .expect("Session trait can only be derived for structs with a session_token field of type Option<Account<'info, SessionToken>> or Option<Account<'info, SessionTokenV2>>");
    let token_type = info.token_type;

    if let Some(expected) = expected {
        if token_type != expected {
            return syn::Error::new_spanned(
                &session_token_field.ty,
                "#[derive(SessionV2)] requires Option<Account<'info, SessionTokenV2>>",
            )
            .to_compile_error()
            .into();
        }
    }

    // Session Token field must have the #[session] attribute
    let session_attr = session_token_field
        .attrs
        .iter()
        .find(|attr| is_session(attr))
        .expect("Session trait can only be derived for structs with a session_token field with the #[session] attribute");

    let session_args = session_attr.parse_args::<SessionArgs>().unwrap();

    let session_signer = session_args.signer.right.into_token_stream();

    // Session Authority
    let session_authority = session_args.authority.right.into_token_stream();

    let struct_name = &input_parsed.ident;
    let (impl_generics, ty_generics, where_clause) = input_parsed.generics.split_for_impl();

    // Use the lifetime extracted from the session_token field type (Account<'info, ...>).
    // This ensures we use the exact lifetime from the field, not the struct's first lifetime.
    let info_lifetime = info.lifetime;

    let output = match token_type {
        SessionTokenType::V1 => quote! {
            #[automatically_derived]
            impl #impl_generics ::session_keys::Session<#info_lifetime> for #struct_name #ty_generics #where_clause {

                fn target_program(&self) -> ::anchor_lang::prelude::Pubkey {
                    crate::id()
                }

                fn session_token(&self) -> Option<::anchor_lang::prelude::Account<#info_lifetime, ::session_keys::SessionToken>> {
                    self.session_token.clone()
                }

                fn session_authority(&self) -> ::anchor_lang::prelude::Pubkey {
                    self.#session_authority
                }

                fn session_signer(&self) -> ::anchor_lang::prelude::Signer<#info_lifetime> {
                    self.#session_signer.clone()
                }

            }
        },
        SessionTokenType::V2 => quote! {
            #[automatically_derived]
            impl #impl_generics ::session_keys::SessionV2<#info_lifetime> for #struct_name #ty_generics #where_clause {

                fn target_program(&self) -> ::anchor_lang::prelude::Pubkey {
                    crate::id()
                }

                fn session_token(&self) -> Option<::anchor_lang::prelude::Account<#info_lifetime, ::session_keys::SessionTokenV2>> {
                    self.session_token.clone()
                }

                fn session_authority(&self) -> ::anchor_lang::prelude::Pubkey {
                    self.#session_authority
                }

                fn session_signer(&self) -> ::anchor_lang::prelude::Signer<#info_lifetime> {
                    self.#session_signer.clone()
                }

            }
        },
    };

    output.into()
}

/// Derive macro for the `Session` trait (V1) or `SessionV2` trait.
/// Auto-detects based on the field type:
///   - `Option<Account<'info, SessionToken>>` → implements `Session`
///   - `Option<Account<'info, SessionTokenV2>>` → implements `SessionV2`
#[proc_macro_derive(Session, attributes(session))]
pub fn derive_session(input: TokenStream) -> TokenStream {
    derive_impl(input, None)
}

/// Explicit V2 derive macro — same implementation as `#[derive(Session)]`,
/// provided for clarity when using `SessionTokenV2`.
#[proc_macro_derive(SessionV2, attributes(session))]
pub fn derive_session_v2(input: TokenStream) -> TokenStream {
    derive_impl(input, Some(SessionTokenType::V2))
}

struct SessionAuthArgs(syn::Expr, syn::Expr);

impl Parse for SessionAuthArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let equality_expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let error_expr = input.parse()?;
        Ok(SessionAuthArgs(equality_expr, error_expr))
    }
}

#[proc_macro_attribute]
/// Macro to check if the session (V1 or V2) or the original authority is the signer.
/// Works with both `Session` and `SessionV2` traits.
pub fn session_auth_or(attr: TokenStream, item: TokenStream) -> TokenStream {
    let SessionAuthArgs(auth_expr, error_ty) = parse_macro_input!(attr);

    let input_fn = parse_macro_input!(item as syn::ItemFn);
    let input_fn_name = input_fn.sig.ident;
    let input_fn_vis = input_fn.vis;
    let input_fn_block = input_fn.block;
    let input_fn_inputs = input_fn.sig.inputs;
    let input_fn_output = input_fn.sig.output;

    let output = quote! {
        #input_fn_vis fn #input_fn_name(#input_fn_inputs) #input_fn_output {
            // Automatically generated by session_auth_or macro
            // Import both traits so is_valid()/session_token()/session_authority() resolve
            // regardless of which trait the derive emitted.
            use ::session_keys::{Session as _, SessionV2 as _};
            // BEGIN SESSION AUTH
            // Current signer is the session signer or the original authority
            let session_token = ctx.accounts.session_token();
            if let Some(token) = session_token {
                require!(ctx.accounts.is_valid()?, SessionError::InvalidToken);
                // Checks that authority of the session is the same as authority of the original account
                require_eq!(
                    ctx.accounts.session_authority(),
                    token.authority.key(),
                    #error_ty
                );
            } else {
                require!(
                    #auth_expr,
                    #error_ty
                );
            }
            // END SESSION AUTH
            #input_fn_block
        }
    };
    output.into()
}
