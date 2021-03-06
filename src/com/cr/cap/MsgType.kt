package com.cr.cap

/**
 * Created by wangbo on 16/7/13.
 */
class MsgType {

    companion object {
        var types: Map<Int, String> = mapOf(
                10100 to "ClientHello",
                10101 to "Login",
                10107 to "ClientCapabilities",
                10108 to "KeepAlive",
                10112 to "AuthenticationCheck",
                10113 to "SetDeviceToken",
                10116 to "ResetAccount",
                10117 to "ReportUser",
                10118 to "AccountSwitched",
                10121 to "UnlockAccount",
                10150 to "AppleBillingRequest",
                10151 to "GoogleBillingRequest",
                10159 to "KunlunBillingRequest",
                10212 to "ChangeAvatarName",
                10512 to "AskForPlayingGamecenterFriends",
                10513 to "AskForPlayingFacebookFriends",
                10905 to "InboxOpened",
                12211 to "UnbindFacebookAccount",
                12903 to "RequestSectorState",
                12904 to "SectorCommand",
                12905 to "GetCurrentBattleReplayData",
                12951 to "SendBattleEvent",
                14101 to "GoHome",
                14102 to "EndClientTurn",
                14104 to "StartMission",
                14105 to "HomeLogicStopped",
                14107 to "CancelMatchmake",
                14108 to "ChangeHomeName",
                14113 to "VisitHome",
                14114 to "HomeBattleReplay",
                14117 to "HomeBattleReplayViewed",
                14120 to "AcceptChallenge",
                14123 to "CancelChallengeMessage",
                14201 to "BindFacebookAccount",
                14212 to "BindGamecenterAccount",
                14262 to "BindGoogleServiceAccount",
                14301 to "CreateAlliance",
                14302 to "AskForAllianceData",
                14303 to "AskForJoinableAlliancesList",
                14304 to "AskForAllianceStream",
                14305 to "JoinAlliance",
                14306 to "ChangeAllianceMemberRole",
                14307 to "KickAllianceMember",
                14308 to "LeaveAlliance",
                14310 to "DonateAllianceUnit",
                14315 to "ChatToAllianceStream",
                14316 to "ChangeAllianceSettings",
                14317 to "RequestJoinAlliance",
                14318 to "SelectSpellsFromCoOpen",
                14319 to "OfferChestForCoOpen",
                14321 to "RespondToAllianceJoinRequest",
                14322 to "SendAllianceInvitation",
                14323 to "JoinAllianceUsingInvitation",
                14324 to "SearchAlliances",
                14330 to "SendAllianceMail",
                14401 to "AskForAllianceRankingList",
                14402 to "AskForTVContent",
                14403 to "AskForAvatarRankingList",
                14404 to "AskForAvatarLocalRanking",
                14405 to "AskForAvatarStream",
                14406 to "AskForBattleReplayStream",
                14408 to "AskForLastAvatarTournamentResults",
                14418 to "RemoveAvatarStreamEntry",
                14600 to "AvatarNameCheckRequest",
                16000 to "LogicDeviceLinkCodeStatus",
                20100 to "ServerHello",
                20103 to "LoginFailed",
                20104 to "LoginOk",
                20105 to "FriendList",
                20108 to "KeepAliveOk",
                20118 to "ChatAccountBanStatus",
                20121 to "BillingRequestFailed",
                20132 to "UnlockAccountOk",
                20133 to "UnlockAccountFailed",
                20151 to "AppleBillingProcessedByServer",
                20152 to "GoogleBillingProcessedByServer",
                20156 to "KunlunBillingProcessedByServer",
                20161 to "ShutdownStarted",
                20205 to "AvatarNameChangeFailed",
                20206 to "AvatarOnlineStatusUpdated",
                20207 to "AllianceOnlineStatusUpdated",
                20225 to "BattleResult",
                20300 to "AvatarNahmeCheckResponse",
                20801 to "OpponentLeftMatchNotification",
                20802 to "OpponentRejoinsMatchNotification",
                21902 to "SectorHearbeat",
                21903 to "SectorState",
                22952 to "BattleEvent",
                22957 to "PvpMatchmakeNotification",
                24101 to "OwnHomeData",
                24102 to "OwnAvatarData",
                24104 to "OutOfSync",
                24106 to "StopHomeLogic",
                24107 to "MatchmakeInfo",
                24108 to "MatchmakeFailed",
                24111 to "AvailableServerCommand",
                24112 to "UdpConnectionInfo",
                24113 to "VisitedHomeData",
                24114 to "HomeBattleReplay",
                24115 to "ServerError",
                24116 to "HomeBattleReplayFailed",
                24121 to "ChallengeFailed",
                24124 to "CancelChallengeDone",
                24125 to "CancelMatchmakeDone",
                24201 to "FacebookAccountBound",
                24202 to "FacebookAccountAlreadyBound",
                24212 to "GamecenterAccountAlreadyBound",
                24213 to "FacebookAccountUnbound",
                24261 to "GoogleServiceAccountBound",
                24262 to "GoogleServiceAccountAlreadyBound",
                24301 to "AllianceData",
                24302 to "AllianceJoinFailed",
                24303 to "AllianceJoinOk",
                24304 to "JoinableAllianceList",
                24305 to "AllianceLeaveOk",
                24306 to "ChangeAllianceMemberRoleOk",
                24307 to "KickAllianceMemberOk",
                24308 to "AllianceMember",
                24309 to "AllianceMemberRemoved",
                24310 to "AllianceList",
                24311 to "AllianceStream",
                24312 to "AllianceStreamEntry",
                24318 to "AllianceStreamEntryRemoved",
                24319 to "AllianceJoinRequestOk",
                24320 to "AllianceJoinRequestFailed",
                24321 to "AllianceInvitationSendFailed",
                24322 to "AllianceInvitationSentOk",
                24324 to "AllianceFullEntryUpdate",
                24332 to "AllianceCreateFailed",
                24333 to "AllianceChangeFailed",
                24401 to "AllianceRankingList",
                24402 to "AllianceLocalRankingList",
                24403 to "AvatarRankingList",
                24404 to "AvatarLocalRankingList",
                24405 to "RoyalTVContent",
                24407 to "LastAvatarTournamentResults",
                24411 to "AvatarStream",
                24412 to "AvatarStreamEntry",
                24413 to "BattleReportStream",
                24418 to "AvatarStreamEntryRemoved",
                24445 to "InboxList",
                24447 to "InboxCount",
                25892 to "Disconnected",
                26002 to "LogicDeviceLinkCodeResponse",
                26003 to "LogicDeviceLinkNewDeviceLinked",
                26004 to "LogicDeviceLinkCodeDeactivated",
                26005 to "LogicDeviceLinkResponse",
                26007 to "LogicDeviceLinkDone",
                26008 to "LogicDeviceLinkError"

        )
    }
}


fun main(args: Array<String>) {
    println("hello")
}