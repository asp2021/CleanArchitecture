using CleanArchitecture.Application.Features.Actores.Queries.Vms;
using CleanArchitecture.Application.Features.Shared.Queries;
using MediatR;

namespace CleanArchitecture.Application.Features.Actores.Queries.PaginationActor
{
    public class PaginationActorQuery: PaginationBaseQuery, IRequest<PaginationVm<ActorVm>>
    {
    }
}
