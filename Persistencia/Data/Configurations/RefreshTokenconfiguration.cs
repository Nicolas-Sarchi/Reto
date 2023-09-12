using Dominio.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.Extensions.Configuration;

namespace Persistencia.Data.Configurations
{
  public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
  {
     public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_token");
  }
  }
}