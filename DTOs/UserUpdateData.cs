using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace AtonTask.DTOs
{
    public class UserUpdateData
    {
        [Required]
        [RegularExpression("^[a-zA-Z0-9]*$", ErrorMessage = "Login can only contain english letters and numbers.")]
        public string NewLogin { get; set; }
        [Required]
        [RegularExpression("^[a-zA-Z0-9]*$", ErrorMessage = "Password can only contain english letters and numbers.")]
        public string NewPassword { get; set; }
        [Required]
        [RegularExpression("^[a-zA-Zа-яА-Я]*$", ErrorMessage = "Name can only contain english and russian letters.")]
        public string NewName { get; set; }
        public GenderType? NewGender { get; set; }
        public DateTime? NewBirthDate { get; set; }
    }
}
