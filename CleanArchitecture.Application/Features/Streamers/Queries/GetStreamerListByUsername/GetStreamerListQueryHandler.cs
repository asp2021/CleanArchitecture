using AutoMapper;
using CleanArchitecture.Application.Contracts.Persistence;
using CleanArchitecture.Application.Features.Streamers.Queries.Vms;
using CleanArchitecture.Domain;
using MediatR;
using System.Linq.Expressions;

namespace CleanArchitecture.Application.Features.Streamers.Queries.GetStreamerListByUsername
{
    public class GetStreamerListQueryHandler : IRequestHandler<GetStreamerListQuery, List<StreamersVm>>
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetStreamerListQueryHandler(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<List<StreamersVm>> Handle(GetStreamerListQuery request, CancellationToken cancellationToken)
        {
            var includes = new List<Expression<Func<Streamer, object>>>();
            includes.Add(p => p.Videos!);

            var streamersList = await _unitOfWork.Repository<Streamer>().GetAsync(
                b => b.CreatedBy == request.Username,
                b => b.OrderBy(x => x.CreatedDate),
                includes,
                true);
            return _mapper.Map<List<StreamersVm>>(streamersList);
        }
    }
}
