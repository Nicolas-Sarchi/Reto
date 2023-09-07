using API.Dtos;
namespace API.Services;

public interface IUserService
{
    Task<string> RegisterAsync(RegisterDto model);
    Task<DatosUsuarioDto> GetTokenAsync(LoginDto model);

    Task<string> AddRoleAsync(AddRoleDto model);

}
