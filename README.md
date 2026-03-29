
# Rubeus (ARM version)

---

## ⚡️ Overview

**Rubeus** is a powerful C# tool for Kerberos interaction and abuse, widely used in security testing and Windows network environments. This code is a specific adaptation for **ARM architectures** (e.g., Windows on ARM64), enabling native operation in these environments. The foundation of this project is the original Rubeus code, developed and maintained by the security community, and here only the necessary modifications have been made to ensure compatibility and execution on ARM. **No new features have been added nor has the main logic of the original project been altered**; full credit for the functionality belongs to the original authors.

> **Important note:** If you are looking for the standard x86/x64 version, check the original Rubeus repository. This version only adapts the existing code to work properly on ARM.

# Rubeus (versión ARM)

---

## ⚡️ Superdescripción

**Rubeus** es una poderosa herramienta en C# para la interacción y abuso de Kerberos, ampliamente utilizada en pruebas de seguridad y entornos de red Windows. Este código es una adaptación específica para arquitecturas **ARM** (por ejemplo, Windows en ARM64), permitiendo su funcionamiento nativo en estos entornos. La base de este proyecto es el código original de Rubeus, desarrollado y mantenido por la comunidad de seguridad, y aquí solo se han realizado las modificaciones necesarias para asegurar la compatibilidad y ejecución en ARM. **No se han añadido nuevas funcionalidades ni alterado la lógica principal del proyecto original**; el mérito completo de la funcionalidad corresponde a los autores originales.

> **Nota importante:** Si buscas la versión x86/x64 estándar, consulta el repositorio original de Rubeus. Esta versión solo adapta el código existente para que funcione correctamente en ARM.

---

## 🛠️ Compilation / Compilación

### English

To compile this ARM version of Rubeus, use the following command (requires .NET 8 SDK or later):

```
dotnet publish -c Release -f net8.0 -r win-arm64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

This will generate a single executable file for Windows ARM64 in the `bin/Release/net8.0/win-arm64/publish/` directory.

### Español

Para compilar esta versión ARM de Rubeus, utiliza el siguiente comando (requiere .NET 8 SDK o superior):

```
dotnet publish -c Release -f net8.0 -r win-arm64 --self-contained true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
```

Esto generará un único archivo ejecutable para Windows ARM64 en el directorio `bin/Release/net8.0/win-arm64/publish/`.
