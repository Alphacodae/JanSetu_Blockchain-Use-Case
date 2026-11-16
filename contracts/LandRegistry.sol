// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title JanSetu Government Records
/// @notice Stores opaque references and approvals. Personal and parcel details stay off-chain.
contract LandRegistry {
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 public constant LAND_OFFICE_ROLE = keccak256("LAND_OFFICE_ROLE");
    bytes32 public constant SURVEY_OFFICE_ROLE = keccak256("SURVEY_OFFICE_ROLE");
    bytes32 public constant IDENTITY_ISSUER_ROLE = keccak256("IDENTITY_ISSUER_ROLE");
    bytes32 public constant WELFARE_OPERATOR_ROLE = keccak256("WELFARE_OPERATOR_ROLE");
    bytes32 public constant PDS_ELIGIBILITY = keccak256("PDS_ELIGIBILITY");
    /// @dev Approval mask: bit 0 is land office, bit 1 is survey office; both bits are required.
    uint8 private constant LAND_APPROVAL = 1;
    uint8 private constant SURVEY_APPROVAL = 2;
    uint8 private constant BOTH_DEPARTMENTS = LAND_APPROVAL | SURVEY_APPROVAL;

    error Unauthorized(bytes32 role, address actor);
    error InvalidRole(bytes32 role);
    error ZeroAddress();
    error RoleAlreadyAssigned(bytes32 role, address account);
    error RoleNotAssigned(bytes32 role, address account);
    error LastRoleHolder(bytes32 role);
    error AdminRoleProtected();
    error AdminCannotVerify();
    error DepartmentRolesMustBeSeparate();
    error ParcelAlreadyExists(bytes32 parcelId);
    error ParcelNotFound(bytes32 parcelId);
    error ParcelNotPending(bytes32 parcelId);
    error ParcelNotVerified(bytes32 parcelId);
    error InvalidVerifierRole(bytes32 role);
    error DepartmentAlreadyApproved(bytes32 parcelId, bytes32 role);
    error DepartmentsNeedSeparateAccounts();
    error InvalidReference();
    error TransferAlreadyPending(bytes32 parcelId);
    error NoTransferPending(bytes32 parcelId);
    error OwnerUnchanged();
    error ClaimAlreadyExpired();
    error ClaimNotFound();
    error ClaimNotCurrent();
    error DeliveryAlreadyRecorded(bytes32 referenceHash, bytes32 cycleHash);

    enum State { None, PendingVerification, Verified }

    struct Parcel {
        bytes32 ownerHash;
        bytes32 documentProof;
        State state;
        uint8 registrationApprovals;
        address firstRegistrationVerifier;
        bytes32 pendingOwnerHash;
        uint8 transferApprovals;
        address firstTransferVerifier;
    }

    address public admin;
    address public pendingAdmin;
    mapping(address => mapping(bytes32 => bool)) private roles;
    mapping(bytes32 => uint16) public roleMemberCount;
    mapping(bytes32 => Parcel) private parcels;
    mapping(bytes32 => mapping(bytes32 => uint64)) private eligibilityClaims;
    mapping(bytes32 => mapping(bytes32 => bool)) public deliveryReceipts;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed actor, bytes32 context);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed actor, bytes32 context);
    event AdminTransferProposed(address indexed currentAdmin, address indexed proposedAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event RecordSubmitted(bytes32 indexed parcelId, address indexed registrar);
    event RecordVerified(bytes32 indexed parcelId, address indexed verifier, bytes32 role);
    event TransferRequested(bytes32 indexed parcelId, bytes32 indexed newOwnerHash, address registrar);
    event TransferApproved(bytes32 indexed parcelId, address indexed verifier, bytes32 role);
    event OwnershipUpdated(bytes32 indexed parcelId, bytes32 indexed newOwnerHash);
    event EligibilityClaimIssued(bytes32 indexed referenceHash, bytes32 indexed claimType, uint64 validUntil, address issuer);
    event EligibilityClaimRevoked(bytes32 indexed referenceHash, bytes32 indexed claimType, address issuer);
    event PdsDeliveryRecorded(bytes32 indexed referenceHash, bytes32 indexed cycleHash, bytes32 itemsHash, address operator);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert Unauthorized(bytes32("ADMIN"), msg.sender);
        _;
    }

    modifier onlyRole(bytes32 role) {
        if (!roles[msg.sender][role]) revert Unauthorized(role, msg.sender);
        _;
    }

    constructor() {
        admin = msg.sender;
        _grantRole(REGISTRAR_ROLE, msg.sender, bytes32("DEPLOYMENT"));
    }

    function _isKnownRole(bytes32 role) private pure returns (bool) {
        return role == REGISTRAR_ROLE || role == LAND_OFFICE_ROLE || role == SURVEY_OFFICE_ROLE ||
            role == IDENTITY_ISSUER_ROLE || role == WELFARE_OPERATOR_ROLE;
    }

    function _grantRole(bytes32 role, address account, bytes32 context) private {
        if (!_isKnownRole(role)) revert InvalidRole(role);
        if (account == address(0)) revert ZeroAddress();
        if (roles[account][role]) revert RoleAlreadyAssigned(role, account);
        if (role == LAND_OFFICE_ROLE || role == SURVEY_OFFICE_ROLE) {
            if (account == admin) revert AdminCannotVerify();
            bytes32 other = role == LAND_OFFICE_ROLE ? SURVEY_OFFICE_ROLE : LAND_OFFICE_ROLE;
            if (roles[account][other]) revert DepartmentRolesMustBeSeparate();
        }
        roles[account][role] = true;
        roleMemberCount[role] += 1;
        emit RoleGranted(role, account, msg.sender, context);
    }

    function grantRole(bytes32 role, address account, bytes32 context) external onlyAdmin {
        _grantRole(role, account, context);
    }

    function revokeRole(bytes32 role, address account, bytes32 context) external onlyAdmin {
        if (!_isKnownRole(role)) revert InvalidRole(role);
        if (!roles[account][role]) revert RoleNotAssigned(role, account);
        if (role == REGISTRAR_ROLE && account == admin) revert AdminRoleProtected();
        if (roleMemberCount[role] <= 1) revert LastRoleHolder(role);
        roles[account][role] = false;
        roleMemberCount[role] -= 1;
        emit RoleRevoked(role, account, msg.sender, context);
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return roles[account][role];
    }

    /// @notice Admin handoff is two-step. The current admin remains active until accepted.
    function proposeAdmin(address nextAdmin) external onlyAdmin {
        if (nextAdmin == address(0) || nextAdmin == admin) revert ZeroAddress();
        pendingAdmin = nextAdmin;
        emit AdminTransferProposed(admin, nextAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert Unauthorized(bytes32("PENDING_ADMIN"), msg.sender);
        address previous = admin;
        if (!roles[msg.sender][REGISTRAR_ROLE]) _grantRole(REGISTRAR_ROLE, msg.sender, bytes32("ADMIN_HANDOFF"));
        admin = msg.sender;
        pendingAdmin = address(0);
        if (roles[previous][REGISTRAR_ROLE]) {
            roles[previous][REGISTRAR_ROLE] = false;
            roleMemberCount[REGISTRAR_ROLE] -= 1;
            emit RoleRevoked(REGISTRAR_ROLE, previous, msg.sender, bytes32("ADMIN_HANDOFF"));
        }
        emit AdminTransferred(previous, msg.sender);
    }

    /// @dev `ownerHash` and `documentProof` must be keyed references generated off-chain.
    function submitRecord(bytes32 parcelId, bytes32 ownerHash, bytes32 documentProof)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        if (parcelId == bytes32(0) || ownerHash == bytes32(0) || documentProof == bytes32(0)) revert InvalidReference();
        if (parcels[parcelId].state != State.None) revert ParcelAlreadyExists(parcelId);
        parcels[parcelId] = Parcel({
            ownerHash: ownerHash,
            documentProof: documentProof,
            state: State.PendingVerification,
            registrationApprovals: 0,
            firstRegistrationVerifier: address(0),
            pendingOwnerHash: bytes32(0),
            transferApprovals: 0,
            firstTransferVerifier: address(0)
        });
        emit RecordSubmitted(parcelId, msg.sender);
    }

    function verifyRecord(bytes32 parcelId, bytes32 verifierRole) external onlyRole(verifierRole) {
        if (verifierRole != LAND_OFFICE_ROLE && verifierRole != SURVEY_OFFICE_ROLE) revert InvalidVerifierRole(verifierRole);
        Parcel storage parcel = parcels[parcelId];
        if (parcel.state == State.None) revert ParcelNotFound(parcelId);
        if (parcel.state != State.PendingVerification) revert ParcelNotPending(parcelId);
        uint8 bit = verifierRole == LAND_OFFICE_ROLE ? LAND_APPROVAL : SURVEY_APPROVAL;
        if ((parcel.registrationApprovals & bit) != 0) revert DepartmentAlreadyApproved(parcelId, verifierRole);
        if (parcel.firstRegistrationVerifier != address(0) && parcel.firstRegistrationVerifier == msg.sender) revert DepartmentsNeedSeparateAccounts();
        if (parcel.firstRegistrationVerifier == address(0)) parcel.firstRegistrationVerifier = msg.sender;
        parcel.registrationApprovals |= bit;
        emit RecordVerified(parcelId, msg.sender, verifierRole);
        if (parcel.registrationApprovals == BOTH_DEPARTMENTS) parcel.state = State.Verified;
    }

    function requestTransfer(bytes32 parcelId, bytes32 newOwnerHash) external onlyRole(REGISTRAR_ROLE) {
        Parcel storage parcel = parcels[parcelId];
        if (parcel.state == State.None) revert ParcelNotFound(parcelId);
        if (parcel.state != State.Verified) revert ParcelNotVerified(parcelId);
        if (newOwnerHash == bytes32(0)) revert InvalidReference();
        if (newOwnerHash == parcel.ownerHash) revert OwnerUnchanged();
        if (parcel.pendingOwnerHash != bytes32(0)) revert TransferAlreadyPending(parcelId);
        parcel.pendingOwnerHash = newOwnerHash;
        parcel.transferApprovals = 0;
        parcel.firstTransferVerifier = address(0);
        emit TransferRequested(parcelId, newOwnerHash, msg.sender);
    }

    function approveTransfer(bytes32 parcelId, bytes32 verifierRole) external onlyRole(verifierRole) {
        if (verifierRole != LAND_OFFICE_ROLE && verifierRole != SURVEY_OFFICE_ROLE) revert InvalidVerifierRole(verifierRole);
        Parcel storage parcel = parcels[parcelId];
        if (parcel.state == State.None) revert ParcelNotFound(parcelId);
        if (parcel.pendingOwnerHash == bytes32(0)) revert NoTransferPending(parcelId);
        uint8 bit = verifierRole == LAND_OFFICE_ROLE ? LAND_APPROVAL : SURVEY_APPROVAL;
        if ((parcel.transferApprovals & bit) != 0) revert DepartmentAlreadyApproved(parcelId, verifierRole);
        if (parcel.firstTransferVerifier != address(0) && parcel.firstTransferVerifier == msg.sender) revert DepartmentsNeedSeparateAccounts();
        if (parcel.firstTransferVerifier == address(0)) parcel.firstTransferVerifier = msg.sender;
        parcel.transferApprovals |= bit;
        emit TransferApproved(parcelId, msg.sender, verifierRole);
        if (parcel.transferApprovals == BOTH_DEPARTMENTS) {
            parcel.ownerHash = parcel.pendingOwnerHash;
            parcel.pendingOwnerHash = bytes32(0);
            parcel.transferApprovals = 0;
            parcel.firstTransferVerifier = address(0);
            emit OwnershipUpdated(parcelId, parcel.ownerHash);
        }
    }

    function getParcel(bytes32 parcelId)
        external
        view
        returns (bytes32 ownerHash, bytes32 documentProof, State state, uint8 registrationApprovals,
            address firstRegistrationVerifier, bytes32 pendingOwnerHash, uint8 transferApprovals,
            address firstTransferVerifier)
    {
        Parcel storage parcel = parcels[parcelId];
        if (parcel.state == State.None) revert ParcelNotFound(parcelId);
        return (parcel.ownerHash, parcel.documentProof, parcel.state, parcel.registrationApprovals,
            parcel.firstRegistrationVerifier, parcel.pendingOwnerHash, parcel.transferApprovals,
            parcel.firstTransferVerifier);
    }

    function issueEligibilityClaim(bytes32 referenceHash, bytes32 claimType, uint64 validUntil)
        external
        onlyRole(IDENTITY_ISSUER_ROLE)
    {
        if (referenceHash == bytes32(0) || claimType == bytes32(0)) revert InvalidReference();
        if (validUntil <= block.timestamp) revert ClaimAlreadyExpired();
        eligibilityClaims[referenceHash][claimType] = validUntil;
        emit EligibilityClaimIssued(referenceHash, claimType, validUntil, msg.sender);
    }

    function revokeEligibilityClaim(bytes32 referenceHash, bytes32 claimType)
        external
        onlyRole(IDENTITY_ISSUER_ROLE)
    {
        if (eligibilityClaims[referenceHash][claimType] == 0) revert ClaimNotFound();
        delete eligibilityClaims[referenceHash][claimType];
        emit EligibilityClaimRevoked(referenceHash, claimType, msg.sender);
    }

    /// @notice A claim is current only while its stored expiry is strictly later than block.timestamp.
    function verifyEligibilityClaim(bytes32 referenceHash, bytes32 claimType) external view returns (bool) {
        return eligibilityClaims[referenceHash][claimType] > block.timestamp;
    }

    function recordPdsDelivery(bytes32 referenceHash, bytes32 cycleHash, bytes32 itemsHash)
        external
        onlyRole(WELFARE_OPERATOR_ROLE)
    {
        if (referenceHash == bytes32(0) || cycleHash == bytes32(0) || itemsHash == bytes32(0)) revert InvalidReference();
        if (eligibilityClaims[referenceHash][PDS_ELIGIBILITY] <= block.timestamp) revert ClaimNotCurrent();
        if (deliveryReceipts[referenceHash][cycleHash]) revert DeliveryAlreadyRecorded(referenceHash, cycleHash);
        deliveryReceipts[referenceHash][cycleHash] = true;
        emit PdsDeliveryRecorded(referenceHash, cycleHash, itemsHash, msg.sender);
    }
}
