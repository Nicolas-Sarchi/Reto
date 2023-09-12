namespace Dominio.Entities;

public class RefreshToken : BaseEntity
{
    public int UserId { get; set; } 
    public string Token { get; set; } 
    public DateTime ExpirationDate { get; set; }
}
