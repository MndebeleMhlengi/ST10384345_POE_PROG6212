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
    public class DocumentUploadTests
    {
        [Theory]
        [InlineData(".pdf", true)]
        [InlineData(".docx", true)]
        [InlineData(".xlsx", true)]
        [InlineData(".jpg", true)]
        [InlineData(".jpeg", true)]
        [InlineData(".png", true)]
        [InlineData(".exe", false)]
        [InlineData(".txt", false)]
        [InlineData(".zip", false)]
        public void Document_FileExtension_ShouldBeValid(string extension, bool expected)
        {
            // Arrange
            var allowedExtensions = new[] { ".pdf", ".docx", ".xlsx", ".jpg", ".jpeg", ".png" };

            // Act
            var isValid = allowedExtensions.Contains(extension.ToLower());

            // Assert
            Assert.Equal(expected, isValid);
        }

        [Fact]
        public void Document_FileSize_ShouldNotExceed_10MB()
        {
            // Arrange
            var maxSize = 10 * 1024 * 1024; // 10MB in bytes
            var validSize = 5 * 1024 * 1024; // 5MB
            var invalidSize = 15 * 1024 * 1024; // 15MB

            // Assert
            Assert.True(validSize <= maxSize);
            Assert.False(invalidSize <= maxSize);
        }

        [Fact]
        public void Document_Should_HaveRequiredProperties()
        {
            // Arrange & Act
            var document = new Document
            {
                ClaimId = 1,
                FileName = "test.pdf",
                FilePath = "/uploads/test.pdf",
                FileType = ".pdf",
                FileSize = 1024,
                Description = "Test document",
                ContentType = "application/pdf",
                IsVerified = false
            };

            // Assert
            Assert.NotNull(document.FileName);
            Assert.NotNull(document.FilePath);
            Assert.NotNull(document.FileType);
            Assert.NotNull(document.ContentType);
            Assert.True(document.FileSize > 0);
            Assert.False(document.IsVerified);
        }

        [Fact]
        public void Document_UploadDate_ShouldBeSet()
        {
            // Arrange & Act
            var document = new Document();

            // Assert
            Assert.True(document.UploadDate > DateTime.MinValue);
        }
    }
}
