using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
namespace AtonTask.Models
{
    public class User
    {
        [Key]
        public Guid Guid { get; set; }
        [Required]
        [RegularExpression("^[a-zA-Z0-9]*$",ErrorMessage ="Login can only contain english letters and numbers.")]
        public string Login {  get; set; }
        [Required]
        [RegularExpression("^[a-zA-Z0-9]*$", ErrorMessage = "Password can only contain english letters and numbers.")]
        public string Password { get; set; }
        [Required]
        [RegularExpression("^[a-zA-Z0-9а-яА-Я]*$", ErrorMessage = "Name can only contain english and russian letters.")]
        public string Name { get; set; }
        [Required]
        [Range(0, 2, ErrorMessage = "Gender must be between 0 (female), 1 (male), or 2 (unknown).")]
        public int Gender { get; set; }
        public DateTime? BirthDay { get; set; }
        [Required]
        public bool Admin { get; set; }
        [Required]
        public DateTime CreatedOn { get; set; }
        [Required]
        public string CreatedBy { get; set; }
        public DateTime ModifiedOn { get; set; }
        public string ModifiedBy { get; set; }
        public DateTime RevokedOn { get; set; } = DateTime.MinValue;
        public string RevokedBy { get; set; }
    }
}
