use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::config::{
            ApproveJoinRequestRequest, ApproveJoinRequestResponse, FetchPendingMemberCertRequest,
            FetchPendingMemberCertResponse, ListPendingJoinRequestsRequest,
            ListPendingJoinRequestsResponse, RejectJoinRequestRequest, RejectJoinRequestResponse,
            SubmitJoinRequestRequest, SubmitJoinRequestResponse, TrustJoinManageRpc,
            UpgradePeerToRootRequest, UpgradePeerToRootResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

#[derive(Clone)]
pub struct TrustJoinManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl TrustJoinManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl TrustJoinManageRpc for TrustJoinManageRpcService {
    type Controller = BaseController;

    async fn submit_join_request(
        &self,
        ctrl: Self::Controller,
        input: SubmitJoinRequestRequest,
    ) -> Result<SubmitJoinRequestResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_trust_join_manage_service()
            .submit_join_request(ctrl, input)
            .await
    }

    async fn fetch_pending_member_cert(
        &self,
        ctrl: Self::Controller,
        input: FetchPendingMemberCertRequest,
    ) -> Result<FetchPendingMemberCertResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_trust_join_manage_service()
            .fetch_pending_member_cert(ctrl, input)
            .await
    }

    async fn approve_join_request(
        &self,
        ctrl: Self::Controller,
        input: ApproveJoinRequestRequest,
    ) -> Result<ApproveJoinRequestResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_trust_join_manage_service()
            .approve_join_request(ctrl, input)
            .await
    }

    async fn reject_join_request(
        &self,
        ctrl: Self::Controller,
        input: RejectJoinRequestRequest,
    ) -> Result<RejectJoinRequestResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_trust_join_manage_service()
            .reject_join_request(ctrl, input)
            .await
    }

    async fn upgrade_peer_to_root(
        &self,
        ctrl: Self::Controller,
        input: UpgradePeerToRootRequest,
    ) -> Result<UpgradePeerToRootResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_trust_join_manage_service()
            .upgrade_peer_to_root(ctrl, input)
            .await
    }

    async fn list_pending_join_requests(
        &self,
        ctrl: Self::Controller,
        input: ListPendingJoinRequestsRequest,
    ) -> Result<ListPendingJoinRequestsResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_trust_join_manage_service()
            .list_pending_join_requests(ctrl, input)
            .await
    }
}
