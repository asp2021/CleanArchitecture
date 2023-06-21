using AutoMapper;
using CleanArchitecture.Application.Contracts.Persistence;
using CleanArchitecture.Application.Features.Actores.Queries.Vms;
using CleanArchitecture.Application.Features.Shared.Queries;
using CleanArchitecture.Application.Specifications.Actores;
using CleanArchitecture.Domain;
using MediatR;

namespace CleanArchitecture.Application.Features.Actores.Queries.PaginationActor
{
    public class PaginationActorQueryHandler : IRequestHandler<PaginationActorQuery, PaginationVm<ActorVm>>
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public PaginationActorQueryHandler(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<PaginationVm<ActorVm>> Handle(PaginationActorQuery request, CancellationToken cancellationToken)
        {
            var actorsSpecificationParams = new ActorSpecificationParams
            {
                PageIndex = request.PageIndex,
                PageSize = request.PageSize,
                Search = request.Search,
                Sort = request.Sort
            };

            var spec = new ActorSpecification(actorsSpecificationParams);
            var actores = await _unitOfWork.Repository<Actor>().GetAllWithSpec(spec);

            var specCount = new ActorForCountingSpecification(actorsSpecificationParams);

            var totalActors = await _unitOfWork.Repository<Actor>().CountAsync(specCount);

            var rounded = Math.Ceiling(Convert.ToDecimal(totalActors) / Convert.ToDecimal(actorsSpecificationParams.PageSize));
            var totalPages = Convert.ToInt32(rounded);

            var data = _mapper.Map<IReadOnlyList<Actor>, IReadOnlyList<ActorVm>>(actores);

            var pagination = new PaginationVm<ActorVm>
            {
                Count = totalActors,
                Data = data,
                PageCount = totalPages,
                PageIndex = request.PageIndex,
                PageSize = request.PageSize
            };

            return pagination;
        }
    }
}
