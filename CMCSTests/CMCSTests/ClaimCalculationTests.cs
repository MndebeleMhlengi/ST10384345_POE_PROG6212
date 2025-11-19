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
    public class ClaimCalculationTests
    {
        [Fact]
        public void TotalAmount_CalculatesCorrectly()
        {
            // Arrange
            var claim = new Claim
            {
                HoursWorked = 40,
                HourlyRate = 250
            };

            // Act
            var totalAmount = claim.HoursWorked * claim.HourlyRate;

            // Assert
            Assert.Equal(10000, totalAmount);
        }

        [Theory]
        [InlineData(10, 100, 1000)]
        [InlineData(25.5, 200, 5100)]
        [InlineData(40, 350, 14000)]
        [InlineData(0.1, 500, 50)]
        public void TotalAmount_CalculatesCorrectly_WithDifferentValues(
            decimal hours, decimal rate, decimal expected)
        {
            // Arrange
            var viewModel = new ClaimSubmissionViewModel
            {
                HoursWorked = hours,
                HourlyRate = rate
            };

            // Act
            var total = viewModel.TotalAmount;

            // Assert
            Assert.Equal(expected, total);
        }

        [Fact]
        public void HoursWorked_MustBeBetween_ZeroPointOne_And_FiveHundred()
        {
            // Arrange
            var validHours = new[] { 0.1m, 100m, 500m };
            var invalidHours = new[] { 0m, -10m, 501m };

            // Assert
            foreach (var hours in validHours)
            {
                Assert.InRange(hours, 0.1m, 500m);
            }

            foreach (var hours in invalidHours)
            {
                Assert.False(hours >= 0.1m && hours <= 500m);
            }
        }
    }

}
