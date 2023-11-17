using Application.Bases;
using Domain.Organizations;
using Domain.Policies;
using Domain.Users;
using Domain.Workspaces;
using Microsoft.Extensions.Logging;

namespace Application.Identity;

public class LoginByEmail : IRequest<LoginResult>
{
    public string Email { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;
}

public class LoginByEmailValidator : AbstractValidator<LoginByEmail>
{
    public LoginByEmailValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty().WithErrorCode(ErrorCodes.Required("email"))
            .EmailAddress().WithErrorCode(ErrorCodes.Invalid("email"));

        RuleFor(x => x.Password)
            .NotEmpty().WithErrorCode(ErrorCodes.Required("password"));
    }
}

public class LoginByEmailHandler : IRequestHandler<LoginByEmail, LoginResult>
{
    private readonly IIdentityService _identityService;
    private readonly IUserService _userService;
    private readonly IWorkspaceService _workspaceService;
    private readonly IOrganizationService _orgService;
    private readonly ILogger<LoginByEmailHandler> _logger;

    public LoginByEmailHandler(
        IIdentityService identityService,
        IUserService userService,
        IWorkspaceService workspaceService,
        IOrganizationService orgService,
        ILogger<LoginByEmailHandler> logger)
    {
        _identityService = identityService;
        _userService = userService;
        _workspaceService = workspaceService;
        _orgService = orgService;
        _logger = logger;
    }

    public async Task<LoginResult> Handle(LoginByEmail request, CancellationToken cancellationToken)
    {
        _logger.LogInformation("user {Identity} login by password", request.Email);

        Guid workspaceId;
        var user = await _userService.FindOneAsync(x => x.Email == request.Email);
        if (user == null)
        {
            // create workspace
            workspaceId = await CreateWorkspaceAsync();

            // create user
            var registerResult = await _identityService.RegisterByEmailAsync(workspaceId, request.Email, request.Password, UserOrigin.Local);
            _logger.LogInformation("user {Identity} registered", request.Email);

            // create organization for new user
            var orgName = $"Playground - {request.Email}";
            var organization = new Organization(workspaceId, orgName);
            await _orgService.AddOneAsync(organization);

            // set user as org owner
            var organizationUser = new OrganizationUser(organization.Id, registerResult.UserId);
            var policies = new[] { BuiltInPolicy.Owner };
            await _orgService.AddUserAsync(organizationUser, policies: policies);
            return LoginResult.Ok(registerResult.Token);
        }

        var workspaces = await _userService.GetWorkspacesAsync(request.Email);
        if (!workspaces.Any())
        {
            // if there is no workspace associated with the user, create one
            workspaceId = await CreateWorkspaceAsync();
        }
        else
        {
            workspaceId = workspaces.First().Id;
        }

        return await _identityService.LoginByEmailAsync(workspaceId, request.Email, request.Password);

        async Task<Guid> CreateWorkspaceAsync()
        {
            var workspace = new Workspace
            {
                Name = "Default Workspace",
                Key = "default-workspace",
                License = null,
                Sso = null
            };
            await _workspaceService.AddOneAsync(workspace);

            return workspace.Id;
        }
    }
}