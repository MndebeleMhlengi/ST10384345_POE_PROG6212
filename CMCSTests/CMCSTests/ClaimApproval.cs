using Xunit;
using CMCS.Models;
using CMCS.Models.ViewModels;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Text;
using Assert = Xunit.Assert;

namespace CMCSTests
{
    public class ClaimApprovalTests
    {
        [Fact]
        public void ClaimApproval_Should_HaveDefaultValues()
        {
            // Arrange & Act
            var approval = new ClaimApproval();

            // Assert
            Assert.Equal(ApprovalStatus.PENDING, approval.Status);
            Assert.True(approval.IsActive);
            Assert.True(approval.ReviewDate > DateTime.MinValue);
        }

        [Fact]
        public void ClaimApproval_Should_HaveRequiredProperties()
        {
            // Arrange & Act
            var approval = new ClaimApproval
            {
                ClaimId = 1,
                ApproverId = 2,
                Level = ApprovalLevel.PROGRAMME_COORDINATOR,
                Status = ApprovalStatus.APPROVED,
                Comments = "Approved with comments",
                RejectionReason = ""
            };

            // Assert
            Assert.True(approval.ClaimId > 0);
            Assert.True(approval.ApproverId > 0);
            Assert.True(Enum.IsDefined(typeof(ApprovalLevel), approval.Level));
            Assert.True(Enum.IsDefined(typeof(ApprovalStatus), approval.Status));
        }

        [Theory]
        [InlineData(ApprovalLevel.PROGRAMME_COORDINATOR)]
        [InlineData(ApprovalLevel.ACADEMIC_MANAGER)]
        [InlineData(ApprovalLevel.HR)]
        public void ApprovalLevel_ShouldBe_ValidEnum(ApprovalLevel level)
        {
            // Assert
            Assert.True(Enum.IsDefined(typeof(ApprovalLevel), level));
        }

        [Theory]
        [InlineData(ApprovalStatus.PENDING)]
        [InlineData(ApprovalStatus.APPROVED)]
        [InlineData(ApprovalStatus.REJECTED)]
        [InlineData(ApprovalStatus.PENDING_CLARIFICATION)]
        public void ApprovalStatus_ShouldBe_ValidEnum(ApprovalStatus status)
        {
            // Assert
            Assert.True(Enum.IsDefined(typeof(ApprovalStatus), status));
        }
    }
}










