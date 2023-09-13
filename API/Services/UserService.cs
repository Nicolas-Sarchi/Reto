using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using API.Dtos;
using API.Helpers;
using Dominio.Entities;
using Dominio.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;

namespace API.Services;

public class UserService : IUserService
{
    private readonly JWT _jwt;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IPasswordHasher<User> _passwordHasher;
    


    public UserService(IUnitOfWork unitOfWork, IOptions<JWT> jwt, IPasswordHasher<User> passwordHasher)
    {
        _unitOfWork = unitOfWork;
        _jwt = jwt.Value;
        _passwordHasher = passwordHasher;

    }
    public async Task<string> RegisterAsync(RegisterDto registerDto)
    {
        var usuario = new User
        {
            UserEmail = registerDto.UserEmail,
            UserName = registerDto.UserName,
        };

        usuario.UserPassword = _passwordHasher.HashPassword(usuario, registerDto.UserPassword);

        var usuarioExiste = _unitOfWork.Users
                                        .Find(u => u.UserName.ToLower() == registerDto.UserName.ToLower())
                                        .FirstOrDefault();

        if(usuarioExiste == null)
        {
            try
            {
                _unitOfWork.Users.Add(usuario);
                await _unitOfWork.SaveAsync();

                return $"El usuario {registerDto.UserName} ha sido creado exitosamente ";

            }
            catch (Exception ex)
            {
                var message = ex.Message;
                return $"Error: {message}";
            }
        }         
        else
        {
            return $"El usuario {registerDto.UserName} ya se encuentra registrado";
        }                       
    }

    public async Task<string> AddRoleAsync (AddRoleDto model)
    {
        var usuario = await _unitOfWork.Users.GetByUserNameAsync(model.UserName);

        if (usuario == null)
        {
            return $"No existe algun usuario registrado con la cuenta, olvidó algún caracter? {model.UserName}.";
        }

        var resultado = _passwordHasher.VerifyHashedPassword(usuario, usuario.UserPassword, model.UserPassword);
        if (resultado == PasswordVerificationResult.Success)
        {
            var rolExiste = _unitOfWork.Rols.Find(u => u.Nombre.ToLower() == model.Rol.ToLower()).FirstOrDefault();
            
            if(rolExiste != null)
            {
                var usuarioTieneRol = usuario.Rols.Any(u => u.Id == rolExiste.Id);

                if (usuarioTieneRol == false)
                {
                    usuario.Rols.Add(rolExiste);
                    _unitOfWork.Users.Update(usuario);
                    await _unitOfWork.SaveAsync();
                }
                return $"Rol {model.Rol} agregado a la cuenta {model.UserName} de forma exitosa";
            }
            return $"Rol {model.Rol} no Encontrado";
        }
          return $"Credenciales incorrectas para el usuario {usuario.UserName}";
    }

    public async Task<DatosUsuarioDto> GetTokenAsync(LoginDto model)
    {
        DatosUsuarioDto datosUsuarioDto = new DatosUsuarioDto();
        var user = await _unitOfWork.Users
                    .GetByUserNameAsync(model.UserName);

        if (user == null)
        {
            datosUsuarioDto.EstaAutenticado = false;
            datosUsuarioDto.Mensaje = $"User does not exist with username {model.UserName}.";
            return datosUsuarioDto;
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.UserPassword, model.UserPassword);

        if (result == PasswordVerificationResult.Success)
        {
            datosUsuarioDto.Mensaje = "OK";
            datosUsuarioDto.EstaAutenticado = true;
            JwtSecurityToken jwtSecurityToken = CreateJwtToken(user);
            datosUsuarioDto.AccesToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            datosUsuarioDto.UserEmail = user.UserEmail;
            datosUsuarioDto.UserName = user.UserName;
            datosUsuarioDto.Roles = user.Rols
                                            .Select(u => u.Nombre)
                                            .ToList();
            datosUsuarioDto.Expiration = DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes);

            datosUsuarioDto.RefreshToken = CreateRefreshToken(user.UserName).ToString("D");
            return datosUsuarioDto;
        }
        datosUsuarioDto.EstaAutenticado = false;
        datosUsuarioDto.Mensaje = $"Credenciales incorrectas para el usuario {user.UserName}.";
        return datosUsuarioDto;
    }
    public async Task<DatosUsuarioDto> GetTokenAsync(AuthenticationTokenResultDto model)
    {
        if (!IsValid(model, out string UserName))
        {
            return null;
        }
        DatosUsuarioDto datosUsuarioDto = new DatosUsuarioDto();
        var user = await _unitOfWork.Users
                    .GetByUserNameAsync(UserName);

        if (user == null)
        {
            datosUsuarioDto.EstaAutenticado = false;
            datosUsuarioDto.Mensaje = $"User does not exist with username {UserName}.";
            return datosUsuarioDto;
        }
            datosUsuarioDto.Mensaje = "OK";
            datosUsuarioDto.EstaAutenticado = true;
            JwtSecurityToken jwtSecurityToken = CreateJwtToken(user);
            datosUsuarioDto.AccesToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            datosUsuarioDto.UserEmail = user.UserEmail;
            datosUsuarioDto.UserName = user.UserName;
            datosUsuarioDto.Roles = user.Rols
                                            .Select(u => u.Nombre)
                                            .ToList();
            datosUsuarioDto.Expiration = DateTime.UtcNow.AddMinutes(_jwt.DurationInMinutes);

            datosUsuarioDto.RefreshToken = CreateRefreshToken(user.UserName).ToString("D");
            return datosUsuarioDto;

    }

    private bool IsValid(AuthenticationTokenResultDto model, out string userName)
    {
        userName = String.Empty;
        ClaimsPrincipal principal = GetPrincipalFromExpiredtoken(model.AccesToken);
        
        if (principal == null)
        {
            throw new UnauthorizedAccessException("No hay Token de Acceso");
        }

        userName = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        if(string.IsNullOrEmpty(userName))
        {
            throw new UnauthorizedAccessException("El userName es nulo o esta vacio");
        }

        if (!Guid.TryParse(model.RefreshToken, out Guid givenRefreshToken))
        {
            throw new UnauthorizedAccessException("El Refresh Token esta mal formado");
        }

        if (!_refreshTokens.TryGetValue(userName, out Guid currentRefreshToken))
        {
            throw new UnauthorizedAccessException("El refresh token no es valido en el sistema");
        }

        if(currentRefreshToken != givenRefreshToken)
        {
            throw new UnauthorizedAccessException("EL refresh token enviado en invalido");
        }
        return true;
    }

    private ClaimsPrincipal GetPrincipalFromExpiredtoken(string accesToken)
    {
        TokenValidationParameters tokenValidationParameters = new TokenValidationParameters{
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false,
            ValidIssuer = _jwt.Issuer,
            ValidAudience = _jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key))
        };

        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        ClaimsPrincipal principal = tokenHandler.ValidateToken(accesToken, tokenValidationParameters, out SecurityToken securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCulture))
        {
            throw new UnauthorizedAccessException("El token es Invalido");
        }
        return principal;
    }

    private static readonly ConcurrentDictionary<string, Guid> _refreshTokens = new ConcurrentDictionary<string, Guid>();
    private Guid CreateRefreshToken(string username)
    {
        Guid newRefreshToken = _refreshTokens.AddOrUpdate(username, Guid.NewGuid(), (s, e) => Guid.NewGuid());
            return newRefreshToken;
        }
    
private JwtSecurityToken CreateJwtToken(User usuario)
{
    if (usuario == null)
    {
        throw new ArgumentNullException(nameof(usuario), "El usuario no puede ser nulo.");
    }

    var roles = usuario.Rols;
    var roleClaims = new List<Claim>();
    foreach (var role in roles)
    {
        roleClaims.Add(new Claim("roles", role.Nombre));
    }

    var claims = new[]
    {
                new Claim(JwtRegisteredClaimNames.Sub, usuario.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("uid", usuario.Id.ToString())
            }
    .Union(roleClaims);

    if (string.IsNullOrEmpty(_jwt.Key) || string.IsNullOrEmpty(_jwt.Issuer) || string.IsNullOrEmpty(_jwt.Audience))
    {
        throw new ArgumentNullException("La configuración del JWT es nula o vacía.");
    }

    var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));

    var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);

    var JwtSecurityToken = new JwtSecurityToken(
        issuer: _jwt.Issuer,
        audience: _jwt.Audience,
        claims: claims,
        expires: DateTime.UtcNow.AddSeconds(_jwt.DurationInMinutes),
        signingCredentials: signingCredentials);

    return JwtSecurityToken;
}
}

