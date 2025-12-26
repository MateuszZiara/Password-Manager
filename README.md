# Menadżer Haseł

Aplikacja webowa służąca do bezpiecznego przechowywania danych logowania, zrealizowana w oparciu o środowisko .NET 9. Głównym założeniem projektu jest bezpieczna kryptografia oraz ścisła kontrola dostępu.

Technologie:
*   Backend: ASP.NET Core MVC
*   Baza danych: MS SQL Server + Entity Framework Core
*   Bezpieczeństwo: ASP.NET Core Identity oraz autorska implementacja szyfrowania AES-256 (każdy rekord posiada unikalny wektor inicjujący IV).
*   Uwierzytelnianie: Wymuszona weryfikacja dwuetapowa (2FA/TOTP) kompatybilna z aplikacjami Microsoft i Google Authenticator.
*   Frontend: Bootstrap 5 + Razor Views.

Funkcjonalności:
System wymusza na użytkowniku konfigurację 2FA tuż po rejestracji. Hasła w bazie danych są w pełni zaszyfrowane – nawet administrator bazy nie ma do nich wglądu. Aplikacja posiada wbudowany generator bezpiecznych haseł oraz funkcje ułatwiające kopiowanie danych do schowka.
