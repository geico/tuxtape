use thiserror::Error;

pub type Result<T> = std::result::Result<T, DatabaseBridgeError>;

#[derive(Debug, Error)]
pub enum DatabaseBridgeError {
    #[error("Protobuf conversion error: {missing_field}")]
    FromProtoError { missing_field: String },

    #[error("SQLx error: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] serde_json::Error),
}

impl DatabaseBridgeError {
    pub fn proto_missing_field<S: Into<String>>(missing_field: S) -> Self {
        DatabaseBridgeError::FromProtoError {
            missing_field: missing_field.into(),
        }
    }
}

impl From<DatabaseBridgeError> for tonic::Status {
    fn from(val: DatabaseBridgeError) -> Self {
        match val {
            DatabaseBridgeError::FromProtoError { missing_field } => {
                tonic::Status::invalid_argument(format!("Missing Protobuf field: {missing_field}"))
            }
            DatabaseBridgeError::SqlxError(err) => tonic::Status::internal(format!("{err}")),
            DatabaseBridgeError::DeserializationError(err) => {
                tonic::Status::internal(format!("{err}"))
            }
        }
    }
}
