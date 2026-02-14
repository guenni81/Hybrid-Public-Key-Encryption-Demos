# AGENT.md - Solution Standards for HPKE Demo Projects

This file defines mandatory conventions for all future projects in this solution.
The standards are derived from the existing reference project `HPKE.Mode.Base`.

## Objective
- Consistent workflow for new HPKE demo projects
- Consistent project structure, build properties, and documentation
- Clear separation between educational demos and production-ready cryptography

## Reference Project
- Technical reference: `HPKE.Mode.Base/HPKE.Mode.Base.csproj`
- Code style/scope: `HPKE.Mode.Base/Program.cs`
- Documentation standard: `HPKE.Mode.Base/README.md`, `HPKE.Mode.Base/ARCHITECTURE.md`, `HPKE.Mode.Base/SECURITY.md`

## Naming Conventions
- Project name: `HPKE.Mode.<ModeName>`
- Folder name matches project name
- Namespace matches project name, e.g. `HPKE.Mode.Base`

## Technical Baseline (Mandatory)
- SDK-style project using `Microsoft.NET.Sdk`
- Project type: Console app (`<OutputType>Exe</OutputType>`)
- Target framework: `net10.0`
- Language features:
  - `<ImplicitUsings>enable</ImplicitUsings>`
  - `<Nullable>enable</Nullable>`
- Crypto library:
  - `NSec.Cryptography` as a PackageReference (pin a specific version, no wildcard)

## Project Structure (Minimum)
Each new `HPKE.Mode.*` project must include at least:
- `<ProjectName>.csproj`
- `Program.cs`
- `README.md`
- `ARCHITECTURE.md`
- `SECURITY.md`

## Implementation Principles
- Focus: minimal, understandable educational example
- Clearly reference the RFC and map logic to it in code
- Step-by-step, readable flow (e.g. key generation, KEM, key schedule, AEAD)
- Avoid unnecessary abstraction in demo code
- Handle error cases explicitly and fail clearly (`InvalidOperationException` instead of silent failures)

## Security Rules
- Every demo must be clearly marked as not production-ready
- If secret material is printed, it must be explicitly labeled as demo-only
- `README.md` and `SECURITY.md` must include a production-use exclusion
- Do not claim audits or side-channel resistance without verifiable evidence

## Documentation Standard
For each new project:
- `README.md`
  - Short description
  - Used algorithms/ciphersuite
  - Build/run steps (`dotnet restore`, `dotnet build`, `dotnet run`)
  - Security notice
  - Dependencies
  - AI-generated code notice (if used)
- `ARCHITECTURE.md`
  - Overview and data flow
  - Parameters/IDs and message format
  - Security considerations
- `SECURITY.md`
  - Disclaimer (demo-only)
  - Vulnerability reporting process

## Workflow for New Projects
1. Create a new project folder `HPKE.Mode.<ModeName>`.
2. Create the `csproj` using the technical baseline above.
3. Create initial files: `Program.cs`, `README.md`, `ARCHITECTURE.md`, `SECURITY.md`.
4. Add the new project to the solution file (`.slnx`).
5. Verify build and execution:
   - `dotnet restore`
   - `dotnet build`
   - `dotnet run --project HPKE.Mode.<ModeName>`
6. Verify security and AI-related notices before completion.

## Quality Gates Before Merge
- Project compiles without errors
- Demo runs reproducibly
- Documentation is complete and consistent
- Security disclaimer is present
- No unintended secrets or key material in commit history
