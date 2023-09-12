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
    private static readonly ConcurrentDictionary<string, Guid> _refreshTokens = new ConcurrentDictionary<string, Guid>();


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
        DatosUsuarioDto DatosUsuarioDto = new DatosUsuarioDto();
        var user = await _unitOfWork.Users
                    .GetByUserNameAsync(model.UserName);

        if (user == null)
        {
            DatosUsuarioDto.EstaAutenticado = false;
            DatosUsuarioDto.Mensaje = $"User does not exist with username {model.UserName}.";
            return DatosUsuarioDto;
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.UserPassword, model.UserPassword);

        if (result == PasswordVerificationResult.Success)
        {
            DatosUsuarioDto.EstaAutenticado = true;
            JwtSecurityToken jwtSecurityToken = CreateJwtToken(user);
            DatosUsuarioDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            DatosUsuarioDto.UserEmail = user.UserEmail;
            DatosUsuarioDto.UserName = user.UserName;
            DatosUsuarioDto.Roles = user.Rols
                                            .Select(u => u.Nombre)
                                            .ToList();

            if (user.RefreshTokens.Any(a => a.IsActive))
            {
                var activeRefreshToken = user.RefreshTokens.Where(a => a.IsActive == true).FirstOrDefault();
                DatosUsuarioDto.RefreshToken = activeRefreshToken.Token;
                DatosUsuarioDto.RefreshTokenExpiration = activeRefreshToken.Expires;
            }
            else
            {
                var refreshToken = CreateRefreshToken();
                DatosUsuarioDto.RefreshToken = refreshToken.Token;
                DatosUsuarioDto.RefreshTokenExpiration = refreshToken.Expires;
                user.RefreshTokens.Add(refreshToken);
                _unitOfWork.Users.Update(user);
                await _unitOfWork.SaveAsync();
            }

            return DatosUsuarioDto;
        }
        DatosUsuarioDto.EstaAutenticado = false;
        DatosUsuarioDto.Mensaje = $"Credenciales incorrectas para el usuario {user.UserName}.";
        return DatosUsuarioDto;
    }
    public async Task<DatosUsuarioDto> RefreshTokenAsync(string refreshToken)
    {
        var DatosUsuarioDto = new DatosUsuarioDto();

        var usuario = await _unitOfWork.Users
                        .GetByRefreshTokenAsync(refreshToken);

        if (usuario == null)
        {
            DatosUsuarioDto.EstaAutenticado = false;
            DatosUsuarioDto.Mensaje = $"Token is not assigned to any user.";
            return DatosUsuarioDto;
        }

        var refreshTokenBd = usuario.RefreshTokens.Single(x => x.Token == refreshToken);

        if (!refreshTokenBd.IsActive)
        {
            DatosUsuarioDto.EstaAutenticado = false;
            DatosUsuarioDto.Mensaje = $"Token is not active.";
            return DatosUsuarioDto;
        }
        //Revoque the current refresh token and
        refreshTokenBd.Revoked = DateTime.UtcNow;
        //generate a new refresh token and save it in the database
        var newRefreshToken = CreateRefreshToken();
        usuario.RefreshTokens.Add(newRefreshToken);
        _unitOfWork.Users.Update(usuario);
        await _unitOfWork.SaveAsync();
        //Generate a new Json Web Token 😊
        DatosUsuarioDto.EstaAutenticado = true;
        JwtSecurityToken jwtSecurityToken = CreateJwtToken(usuario);
        DatosUsuarioDto.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        DatosUsuarioDto.UserEmail = usuario.UserEmail;
        DatosUsuarioDto.UserName = usuario.UserName;
        DatosUsuarioDto.Roles = usuario.Rols
                                        .Select(u => u.Nombre)
                                        .ToList();
        DatosUsuarioDto.RefreshToken = newRefreshToken.Token;
        DatosUsuarioDto.RefreshTokenExpiration = newRefreshToken.Expires;
        return DatosUsuarioDto;
    }

    private RefreshToken CreateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var generator = RandomNumberGenerator.Create())
        {
            generator.GetBytes(randomNumber);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomNumber),
                Expires = DateTime.UtcNow.AddDays(10),
                Created = DateTime.UtcNow
            };
        }
    }
    private JwtSecurityToken CreateJwtToken(User usuario)
    {
        if (usuario == null)
        {
            throw new ArgumentNullException(nameof(usuario), "El usuario no puede ser nulo.");
        }

        var roles = usuario.Rols ;
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

