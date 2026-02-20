//! # Network Prover Builder
//!
//! This module provides a builder for the [`NetworkProver`].

use alloy_primitives::Address;

use crate::{prover::NetworkProver, signer::NetworkSigner, NetworkMode, TEE_NETWORK_RPC_URL};

/// A builder for the [`NetworkProver`].
///
/// The builder is used to configure the [`NetworkProver`] before it is built.
#[derive(Default)]
pub struct NetworkProverBuilder {
    pub private_key: Option<String>,
    pub rpc_url: Option<String>,
    pub tee_signers: Option<Vec<Address>>,
    pub signer: Option<NetworkSigner>,
    pub network_mode: Option<NetworkMode>,
}

impl NetworkProverBuilder {
    /// Creates a new [`NetworkProverBuilder`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            private_key: None,
            rpc_url: None,
            tee_signers: None,
            signer: None,
            network_mode: None,
        }
    }

    /// Sets the Secp256k1 private key (same format as the one used by Ethereum).
    ///
    /// # Details
    /// Sets the private key that will be used sign requests sent to the network. By default, the
    /// private key is read from the `NETWORK_PRIVATE_KEY` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_network::NetworkProverBuilder;
    ///
    /// # tokio_test::block_on(async {
    /// let prover = NetworkProverBuilder::new().private_key("...").build().await;
    /// # });
    /// ```
    #[must_use]
    pub fn private_key(mut self, private_key: &str) -> Self {
        self.private_key = Some(private_key.to_string());
        self
    }

    /// Sets the remote procedure call URL.
    ///
    /// # Details
    /// The URL determines the network that the client will connect to. By default, the URL is
    /// read from the `NETWORK_RPC_URL` environment variable.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_network::NetworkProverBuilder;
    ///
    /// # tokio_test::block_on(async {
    /// let prover = NetworkProverBuilder::new().rpc_url("...").build().await;
    /// # });
    /// ```
    #[must_use]
    pub fn rpc_url(mut self, rpc_url: &str) -> Self {
        self.rpc_url = Some(rpc_url.to_string());
        self
    }

    /// Process proofs inside a TEE.
    ///
    /// # Details
    /// In order to keep the inputs private, it is possible to route the proof
    /// requests to a TEE enclave.
    ///
    /// # Example
    /// ```rust,no_run
    /// use sp1_network::NetworkProverBuilder;
    ///
    /// # tokio_test::block_on(async {
    /// let prover = NetworkProverBuilder::new().private().build().await;
    /// # });
    /// ```
    #[must_use]
    pub fn private(mut self) -> Self {
        self.rpc_url = Some(TEE_NETWORK_RPC_URL.to_string());
        self
    }

    /// Sets the list of TEE signers, used for verifying TEE proofs.
    #[must_use]
    pub fn tee_signers(mut self, tee_signers: &[Address]) -> Self {
        self.tee_signers = Some(tee_signers.to_vec());
        self
    }

    /// Sets the network signer to use for signing requests.
    ///
    /// # Details
    /// This method allows you to provide a custom signer implementation, such as AWS KMS or
    /// a local private key signer. If both `signer` and `private_key` are provided, the signer
    /// takes precedence.
    ///
    /// # Examples
    ///
    /// Using a local private key:
    /// ```rust,no_run
    /// use sp1_network::{signer::NetworkSigner, NetworkProverBuilder};
    ///
    /// # tokio_test::block_on(async {
    /// let private_key = "...";
    /// let signer = NetworkSigner::local(private_key).unwrap();
    /// let prover = NetworkProverBuilder::new().signer(signer).build().await;
    /// # });
    /// ```
    ///
    /// Using AWS KMS:
    /// ```rust,no_run
    /// use sp1_network::{signer::NetworkSigner, NetworkProverBuilder};
    ///
    /// # tokio_test::block_on(async {
    /// let kms_key_arn = "arn:aws:kms:us-east-1:123456789:key/key-id";
    /// let signer = NetworkSigner::aws_kms(kms_key_arn).await.unwrap();
    /// let prover = NetworkProverBuilder::new().signer(signer).build().await;
    /// # });
    /// ```
    #[must_use]
    pub fn signer(mut self, signer: NetworkSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Builds a [`NetworkProver`].
    ///
    /// # Details
    /// This method will build a [`NetworkProver`] with the given parameters. If `signer` is
    /// provided, it will be used directly. Otherwise, if `private_key` is provided, a local
    /// signer will be created from it. If neither is provided, the method will look for the
    /// `NETWORK_PRIVATE_KEY` environment variable.
    ///
    /// # Examples
    ///
    /// Using a private key:
    /// ```rust,no_run
    /// use sp1_network::NetworkProverBuilder;
    ///
    /// # tokio_test::block_on(async {
    /// let prover = NetworkProverBuilder::new().private_key("...").rpc_url("...").build().await;
    /// # });
    /// ```
    ///
    /// Using a local signer:
    /// ```rust,no_run
    /// use sp1_network::{signer::NetworkSigner, NetworkProverBuilder};
    ///
    /// # tokio_test::block_on(async {
    /// let private_key = "...";
    /// let signer = NetworkSigner::local(private_key).unwrap();
    /// let prover = NetworkProverBuilder::new().signer(signer).build().await;
    /// # });
    /// ```
    ///
    /// Using AWS KMS:
    /// ```rust,no_run
    /// use sp1_network::{signer::NetworkSigner, NetworkProverBuilder};
    ///
    /// # tokio_test::block_on(async {
    /// let kms_key_arn = "arn:aws:kms:us-east-1:123456789:key/key-id";
    /// let signer = NetworkSigner::aws_kms(kms_key_arn).await.unwrap();
    /// let prover = NetworkProverBuilder::new().signer(signer).build().await;
    /// # });
    /// ```
    #[must_use]
    pub async fn build(self) -> NetworkProver {
        tracing::info!("initializing network prover");
        let signer = if let Some(provided_signer) = self.signer {
            provided_signer
        } else {
            let private_key = self
                .private_key
                .or_else(|| std::env::var("NETWORK_PRIVATE_KEY").ok().filter(|k| !k.is_empty()))
                .expect(
                    "NETWORK_PRIVATE_KEY environment variable is not set. \
                    Please set it to your private key or use the .private_key() method.",
                );
            NetworkSigner::local(&private_key).expect("Failed to create local signer")
        };

        let network_mode = self.network_mode.unwrap_or_default();

        let rpc_url = match self.rpc_url {
            Some(rpc_url) => rpc_url,
            None => std::env::var("NETWORK_RPC_URL")
                .unwrap_or_else(|_| super::utils::get_default_rpc_url_for_mode(network_mode)),
        };

        let tee_signers = match self.tee_signers {
            Some(tee_signers) => tee_signers,

            #[cfg(feature = "tee-2fa")]
            None => crate::retry::retry_operation(
                || async { crate::tee::get_tee_signers().await.map_err(Into::into) },
                Some(crate::retry::DEFAULT_RETRY_TIMEOUT),
                "get tee signers",
            )
            .await
            .expect("Failed to get TEE signers"),

            #[cfg(not(feature = "tee-2fa"))]
            None => vec![],
        };

        NetworkProver::new(signer, &rpc_url, network_mode).await.with_tee_signers(tee_signers)
    }
}
