using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Persistencia.Data.Migrations
{
    /// <inheritdoc />
    public partial class _6MIg : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_RefreshToken_user_UserId",
                table: "RefreshToken");

            migrationBuilder.DropPrimaryKey(
                name: "PK_RefreshToken",
                table: "RefreshToken");

            migrationBuilder.DropIndex(
                name: "IX_RefreshToken_UserId",
                table: "RefreshToken");

            migrationBuilder.RenameTable(
                name: "RefreshToken",
                newName: "refresh_token");

            migrationBuilder.RenameColumn(
                name: "ExpirationDate",
                table: "refresh_token",
                newName: "Expires");

            migrationBuilder.AddColumn<DateTime>(
                name: "Created",
                table: "refresh_token",
                type: "datetime(6)",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<DateTime>(
                name: "Revoked",
                table: "refresh_token",
                type: "datetime(6)",
                nullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_refresh_token",
                table: "refresh_token",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_token_UserId",
                table: "refresh_token",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_refresh_token_user_UserId",
                table: "refresh_token",
                column: "UserId",
                principalTable: "user",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_refresh_token_user_UserId",
                table: "refresh_token");

            migrationBuilder.DropPrimaryKey(
                name: "PK_refresh_token",
                table: "refresh_token");

            migrationBuilder.DropIndex(
                name: "IX_refresh_token_UserId",
                table: "refresh_token");

            migrationBuilder.DropColumn(
                name: "Created",
                table: "refresh_token");

            migrationBuilder.DropColumn(
                name: "Revoked",
                table: "refresh_token");

            migrationBuilder.RenameTable(
                name: "refresh_token",
                newName: "RefreshToken");

            migrationBuilder.RenameColumn(
                name: "Expires",
                table: "RefreshToken",
                newName: "ExpirationDate");

            migrationBuilder.AddPrimaryKey(
                name: "PK_RefreshToken",
                table: "RefreshToken",
                column: "Id");

            migrationBuilder.CreateIndex(
                name: "IX_RefreshToken_UserId",
                table: "RefreshToken",
                column: "UserId",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_RefreshToken_user_UserId",
                table: "RefreshToken",
                column: "UserId",
                principalTable: "user",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
