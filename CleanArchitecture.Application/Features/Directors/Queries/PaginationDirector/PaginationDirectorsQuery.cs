using CleanArchitecture.Application.Features.Directors.Queries.Vms;
using CleanArchitecture.Application.Features.Shared.Queries;
using MediatR;

namespace CleanArchitecture.Application.Features.Directors.Queries.PaginationDirector
{
    public class PaginationDirectorsQuery: PaginationBaseQuery, IRequest<PaginationVm<DirectorVm>>
    {
    }
}
