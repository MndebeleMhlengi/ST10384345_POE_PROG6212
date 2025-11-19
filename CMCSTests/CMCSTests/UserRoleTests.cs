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

namespace CMCS.Tests
{
    public class UserRoleTests
    {
        [Theory]
        [InlineData(UserRole.LECTURER)]
        [InlineData(UserRole.PROGRAMME_COORDINATOR)]
        [InlineData(UserRole.ACADEMIC_MANAGER)]
        [InlineData(UserRole.HR)]
        [InlineData(UserRole.ADMIN)]
        public void UserRole_ShouldBe_ValidEnum(UserRole role)
        {
            // Assert
            Assert.True(Enum.IsDefined(typeof(UserRole), role));
        }

        [Fact]
        public void User_Should_HaveValidRole()
        {
            // Arrange
            var lecturer = new User { Role = UserRole.LECTURER };
            var coordinator = new User { Role = UserRole.PROGRAMME_COORDINATOR };
            var manager = new User { Role = UserRole.ACADEMIC_MANAGER };
            var hr = new User { Role = UserRole.HR };
            var admin = new User { Role = UserRole.ADMIN };

            // Assert
            Assert.Equal(UserRole.LECTURER, lecturer.Role);
            Assert.Equal(UserRole.PROGRAMME_COORDINATOR, coordinator.Role);
            Assert.Equal(UserRole.ACADEMIC_MANAGER, manager.Role);
            Assert.Equal(UserRole.HR, hr.Role);
            Assert.Equal(UserRole.ADMIN, admin.Role);
        }

        [Fact]
        public void User_Should_HaveRequiredProperties()
        {
            // Arrange & Act
            var user = new User
            {
                FirstName = "John",
                LastName = "Doe",
                Email = "john.doe@university.com",
                Password = "hashedpassword",
                Role = UserRole.LECTURER,
                PhoneNumber = "1234567890",
                Department = "Computer Science",
                HourlyRate = 250.00m,
                EmployeeNumber = "EMP001",
                IsActive = true
            };

            // Assert
            Assert.NotNull(user.FirstName);
            Assert.NotNull(user.LastName);
            Assert.NotNull(user.Email);
            Assert.NotNull(user.Password);
            Assert.True(user.HourlyRate > 0);
            Assert.True(user.IsActive);
        }
    }
}