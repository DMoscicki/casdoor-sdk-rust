use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{utils::null_to_default, Model};

#[cfg_attr(feature = "salvo", derive(salvo::prelude::ToSchema))]
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Enforcer {
    pub owner: String,
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub model: String,
    pub adapter: String,
    #[serde(deserialize_with = "null_to_default")]
    pub model_cfg: HashMap<String, String>,
    pub created_time: String,
    pub updated_time: String,
}
impl Model for Enforcer {
    fn ident() -> &'static str {
        "enforcer"
    }

    fn owner(&self) -> &str {
        &self.owner
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn support_update_columns() -> bool {
        false
    }
}

#[cfg_attr(feature = "salvo", derive(salvo::prelude::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnforceQueryArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_id: Option<String>,
}

pub type CasbinRequest = Vec<String>;

#[cfg_attr(feature = "salvo", derive(salvo::prelude::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EnforceArgs {
    pub query: EnforceQueryArgs,
    pub casbin_request: CasbinRequest,
}

#[cfg_attr(feature = "salvo", derive(salvo::prelude::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BatchEnforceQueryArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_id: Option<String>,
}

#[cfg_attr(feature = "salvo", derive(salvo::prelude::ToSchema))]
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BatchEnforceArgs {
    pub query: BatchEnforceQueryArgs,
    pub casbin_requests: Vec<CasbinRequest>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_enforce_query_args() {
        let mut args = EnforceQueryArgs::default();
        let query_part = serde_urlencoded::to_string(&args).unwrap();
        assert_eq!("", query_part);

        args.permission_id = Some("0".to_owned());
        args.model_id = Some("1".to_owned());
        let query_part = serde_urlencoded::to_string(&args).unwrap();
        assert_eq!("permissionId=0&modelId=1", query_part);
    }
}
