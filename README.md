##  How do Session Keys work?

Docs: https://docs.magicblock.gg/pages/tools/session-keys/how-do-session-keys-work#how-do-session-keys-work

![how_session_keys_work copy](https://github.com/user-attachments/assets/c8b56a00-394f-4b4a-9b6e-878903bf0513)

### What are Session Keys?

Session Keys are meant to be used as secondary signers in your program, especially for frequent interactions like liking a post or moving a piece in a game of chess where constant popups can get in the way of smooth user experience. They are not burner wallets.
Session Keys work in tandem with our on chain program to validate the token and it’s scope.
​
### Session Keys have two components

- An Ephemeral Keypair, intended to be used as a secondary signer in the target program.
- A Session Token, a PDA containing information about expiry and scope of the keypair.

- Ephemeral Keys are stored on the client side, to invoke transactions.
- The transactions invoked by these ephemeral keys are validated in the target program for their validity, expiry and scope.
- Every transaction needs to present both the ephemeral signer and the session token
- This is the general idea behind account abstraction, where instead of just an externally owned key there is also smart contract that enhances security.
