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
    public class ClaimStatusTests
    {
        [Fact]
        public void NewClaim_Should_Have_PendingStatus()
        {
            // Arrange & Act
            var claim = new Claim
            {
                LecturerId = 1,
                MonthWorked = 10,
                YearWorked = 2024,
                HoursWorked = 40,
                HourlyRate = 250,
                ModuleTaught = "PROG6212"
            };

            // Assert
            Assert.Equal(ClaimStatus.PENDING, claim.Status);
            Assert.True(claim.IsActive);
        }

        [Fact]
        public void ClaimStatus_Should_Progress_Correctly()
        {
            // Arrange
            var claim = new Claim
            {
                Status = ClaimStatus.PENDING
            };

            // Act & Assert - Simulate workflow
            claim.Status = ClaimStatus.APPROVED_PC;
            Assert.Equal(ClaimStatus.APPROVED_PC, claim.Status);

            claim.Status = ClaimStatus.APPROVED_FINAL;
            Assert.Equal(ClaimStatus.APPROVED_FINAL, claim.Status);

            claim.Status = ClaimStatus.PAID;
            Assert.Equal(ClaimStatus.PAID, claim.Status);
        }

        [Fact]
        public void ClaimStatus_Rejection_Workflow()
        {
            // Arrange
            var claim = new Claim
            {
                Status = ClaimStatus.PENDING
            };

            // Act
            claim.Status = ClaimStatus.REJECTED;

            // Assert
            Assert.Equal(ClaimStatus.REJECTED, claim.Status);
        }

        [Theory]
        [InlineData(ClaimStatus.PENDING)]
        [InlineData(ClaimStatus.UNDER_REVIEW)]
        [InlineData(ClaimStatus.APPROVED_PC)]
        [InlineData(ClaimStatus.APPROVED_AM)]
        [InlineData(ClaimStatus.APPROVED_FINAL)]
        [InlineData(ClaimStatus.REJECTED)]
        [InlineData(ClaimStatus.PAID)]
        [InlineData(ClaimStatus.CANCELLED)]
        public void ClaimStatus_ShouldBe_ValidEnum(ClaimStatus status)
        {
            // Arrange
            var claim = new Claim { Status = status };

            // Assert
            Assert.True(Enum.IsDefined(typeof(ClaimStatus), claim.Status));
        }
    }
}
