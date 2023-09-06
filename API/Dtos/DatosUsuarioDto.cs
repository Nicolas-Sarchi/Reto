namespace API.Dtos;

public class DatosUsuarioDto
{
    public string Mensaje { get; set;}
    public bool EstaAutenticado { get; set;}
    public string UserName { get; set;}
    public string UserEmail { get; set;}
    public List<string> Roles { get; set;}
    public string token { get; set;}
}
