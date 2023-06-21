using AutoMapper;
using CleanArchitecture.Application.Contracts.Persistence;
using CleanArchitecture.Application.Features.Streamers.Queries.Vms;
using CleanArchitecture.Application.Specifications.Streamers;
using CleanArchitecture.Domain;
using MediatR;

namespace CleanArchitecture.Application.Features.Streamers.Queries.GetStreamerListByUrl
{
    public class GetStreamerListByUrlQueryHandler : IRequestHandler<GetStreamerListByUrlQuery, List<StreamersVm>>
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public GetStreamerListByUrlQueryHandler(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<List<StreamersVm>> Handle(GetStreamerListByUrlQuery request, CancellationToken cancellationToken)
        {
            var spec = new StreamersWithVideosSpecification(request.Url!);
            var streamerList = await _unitOfWork.Repository<Streamer>().GetAllWithSpec(spec);

            return _mapper.Map<List<StreamersVm>>(streamerList);
        }
    }
}
