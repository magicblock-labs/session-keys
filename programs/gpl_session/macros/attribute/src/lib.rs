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

enum SessionTokenType {
    V1,
    V2,
}

fn get_session_token_type(ty: &Type) -> Option<SessionTokenType> {
    let Type::Path(TypePath { path, .. }) = ty else {
        return None;
    };
    let Some(seg) = path.segments.first() else {
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
    let Some(acct_seg) = acct_path.segments.first() else {
        return None;
    };
    if acct_seg.ident != "Account" {
        return None;
    }
    let PathArguments::AngleBracketed(ref acct_args) = acct_seg.arguments else {
        return None;
    };
    let mut args = acct_args.args.iter();
    let Some(GenericArgument::Lifetime(_)) = args.next() else {
        return None;
    };
    let Some(GenericArgument::Type(Type::Path(TypePath { path: st_path, .. }))) = args.next()
    else {
        return None;
    };

    if st_path.segments.len() == 1 {
        if st_path.segments[0].ident == "SessionToken" {
            return Some(SessionTokenType::V1);
        } else if st_path.segments[0].ident == "SessionTokenV2" {
            return Some(SessionTokenType::V2);
        }
    }
    None
}

// Macro to derive Session Trait (supports both SessionToken and SessionTokenV2)
#[proc_macro_derive(SessionV2, attributes(session))]
pub fn derive(input: TokenStream) -> TokenStream {
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
        .find(|field| *field.ident.as_ref().unwrap() == "session_token")
        .expect("Session trait can only be derived for structs with a session_token field");

    let session_token_type = &session_token_field.ty;
    let token_type = get_session_token_type(session_token_type)
        .expect("Session trait can only be derived for structs with a session_token field of type Option<Account<'info, SessionToken>> or Option<Account<'info, SessionTokenV2>>");

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

    let output = match token_type {
        SessionTokenType::V1 => quote! {
            #[automatically_derived]
            impl #impl_generics Session #ty_generics for #struct_name #ty_generics #where_clause {

                // Target Program
                fn target_program(&self) -> Pubkey {
                    crate::id()
                }

                // Session Token
                fn session_token(&self) -> Option<Account<'info, SessionToken>> {
                    self.session_token.clone()
                }

                // Session Authority
                fn session_authority(&self) -> Pubkey {
                    self.#session_authority
                }

                // Session Signer
                fn session_signer(&self) -> Signer<'info> {
                    self.#session_signer.clone()
                }

            }
        },
        SessionTokenType::V2 => quote! {
            #[automatically_derived]
            impl #impl_generics SessionV2 #ty_generics for #struct_name #ty_generics #where_clause {

                // Target Program
                fn target_program(&self) -> Pubkey {
                    crate::id()
                }

                // Session Token
                fn session_token(&self) -> Option<Account<'info, SessionTokenV2>> {
                    self.session_token.clone()
                }

                // Session Authority
                fn session_authority(&self) -> Pubkey {
                    self.#session_authority
                }

                // Session Signer
                fn session_signer(&self) -> Signer<'info> {
                    self.#session_signer.clone()
                }

            }
        },
    };

    output.into()
}

// Macro to derive SessionV2 Trait (alias for Session macro for backwards compatibility)
#[proc_macro_derive(Session, attributes(session))]
pub fn derive_v2(input: TokenStream) -> TokenStream {
    derive(input)
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
/// Macro to check if the session (V1 or V2) or the original authority is the signer
/// This macro works with both Session and SessionV2 traits
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
