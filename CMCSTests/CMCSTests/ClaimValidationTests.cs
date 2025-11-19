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
    public class ClaimValidationTests
    {
        private List<ValidationResult> ValidateModel(object model)
        {
            var validationResults = new List<ValidationResult>();
            var ctx = new ValidationContext(model, null, null);
            Validator.TryValidateObject(model, ctx, validationResults, true);
            return validationResults;
        }

        [Fact]
        public void ClaimSubmission_WithValidData_ShouldPassValidation()
        {
            // Arrange
            var model = new ClaimSubmissionViewModel
            {
                MonthWorked = 10,
                YearWorked = 2024,
                HoursWorked = 40,
                HourlyRate = 250,
                ModuleTaught = "PROG6212",
                AdditionalNotes = "Test claim submission"
            };

            // Act
            var results = ValidateModel(model);

            // Assert
            Assert.Empty(results);
        }

        [Fact]
        public void ClaimSubmission_WithInvalidMonth_ShouldFailValidation()
        {
            // Arrange
            var model = new ClaimSubmissionViewModel
            {
                MonthWorked = 13, // Invalid month
                YearWorked = 2024,
                HoursWorked = 40,
                HourlyRate = 250,
                ModuleTaught = "PROG6212"
            };

            // Act
            var results = ValidateModel(model);

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.MemberNames.Contains("MonthWorked"));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-10)]
        [InlineData(501)]
        public void ClaimSubmission_WithInvalidHours_ShouldFailValidation(decimal hours)
        {
            // Arrange
            var model = new ClaimSubmissionViewModel
            {
                MonthWorked = 10,
                YearWorked = 2024,
                HoursWorked = hours,
                HourlyRate = 250,
                ModuleTaught = "PROG6212"
            };

            // Act
            var results = ValidateModel(model);

            // Assert
            Assert.NotEmpty(results);
        }

        [Fact]
        public void ClaimSubmission_WithInvalidYear_ShouldFailValidation()
        {
            // Arrange
            var model = new ClaimSubmissionViewModel
            {
                MonthWorked = 10,
                YearWorked = 2019, // Invalid year (before 2020)
                HoursWorked = 40,
                HourlyRate = 250,
                ModuleTaught = "PROG6212"
            };

            // Act
            var results = ValidateModel(model);

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.MemberNames.Contains("YearWorked"));
        }

        [Fact]
        public void ClaimSubmission_ModuleTaught_LengthValidation()
        {
            // Arrange
            var model = new ClaimSubmissionViewModel
            {
                MonthWorked = 10,
                YearWorked = 2024,
                HoursWorked = 40,
                HourlyRate = 250,
                ModuleTaught = new string('A', 101) // Exceeds 100 characters
            };

            // Act
            var results = ValidateModel(model);

            // Assert
            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.MemberNames.Contains("ModuleTaught"));
        }
    }
}
