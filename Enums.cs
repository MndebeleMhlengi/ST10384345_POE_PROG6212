namespace CMCS.Models
{
    /// <summary>
    /// Defines the roles a user can hold within the system, dictating their permissions and workflow position.
    /// </summary>
    public enum UserRole
    {
        // Submits claims for worked hours.
        LECTURER,
        // First level of claim approval and review.
        PROGRAMME_COORDINATOR,
        // Second level of claim approval (often managerial or departmental).
        ACADEMIC_MANAGER,
        // Final level of claim approval and responsible for payment processing.
        HR,
        // Full administrative access to manage users and system settings.
        ADMIN
    }

    /// <summary>
    /// Represents the current stage of a time claim in the processing workflow.
    /// </summary>
    public enum ClaimStatus
    {
        // The claim has been submitted but not yet reviewed. (Initial state)
        PENDING,
        // The claim is actively being reviewed by an approver.
        UNDER_REVIEW,
        // The claim has been approved by the Programme Coordinator.
        APPROVED_PC,
        // The claim has been approved by the Academic Manager.
        APPROVED_AM,
        // The claim has received all necessary approvals and is ready for payment (e.g., approved by HR).
        APPROVED_FINAL,
        // The claim has been denied at any stage of the approval process.
        REJECTED,
        // Payment for the claim has been processed and completed. (Final state)
        PAID,
        // The claim was withdrawn by the lecturer or cancelled by an admin before completion.
        CANCELLED
    }

    /// <summary>
    /// Defines the specific management level responsible for reviewing and approving a claim.
    /// </summary>
    public enum ApprovalLevel
    {
        // First-level approval authority.
        PROGRAMME_COORDINATOR,
        // Second-level approval authority.
        ACADEMIC_MANAGER,
        // Final-level approval authority before payment.
        HR
    }

    /// <summary>
    /// Defines the result of a review action taken by an individual approver.
    /// </summary>
    public enum ApprovalStatus
    {
        // The approval step has not yet been acted upon. (Initial state)
        PENDING,
        // The approver has accepted the claim at their level.
        APPROVED,
        // The approver has denied the claim at their level.
        REJECTED,
        // The approver requires more information or documentation from the lecturer.
        PENDING_CLARIFICATION
    }
}