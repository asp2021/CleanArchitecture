using AutoMapper;
using CleanArchitecture.Application.Contracts.Persistence;
using CleanArchitecture.Application.Features.Shared.Queries;
using CleanArchitecture.Application.Features.Videos.Queries.Vms;
using CleanArchitecture.Application.Specifications.Videos;
using CleanArchitecture.Domain;
using MediatR;

namespace CleanArchitecture.Application.Features.Videos.Queries.PaginationVideos
{
    public class PaginationVideosQueryHandler : IRequestHandler<PaginationVideosQuery, PaginationVm<VideosWithIncludesVm>>
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public PaginationVideosQueryHandler(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<PaginationVm<VideosWithIncludesVm>> Handle(PaginationVideosQuery request, CancellationToken cancellationToken)
        {
            var videoSpecificationParams = new VideoSpecificationParams
            {
                StreamerId = request.StreamerId,
                DirectorId = request.DirectorId,
                PageIndex = request.PageIndex,
                PageSize = request.PageSize,
                Search = request.Search,
                Sort = request.Sort
            };

            var spec = new VideoSpecification(videoSpecificationParams);
            var videos = await _unitOfWork.Repository<Video>().GetAllWithSpec(spec);

            var specCount = new VideoForCountingSpecification(videoSpecificationParams);
            var totalVideos = await _unitOfWork.Repository<Video>().CountAsync(specCount);

            var rounded = Math.Ceiling(Convert.ToDecimal(totalVideos) / Convert.ToDecimal(request.PageSize));
            var totalPages = Convert.ToInt32(rounded);

            var data = _mapper.Map<IReadOnlyList<Video>, IReadOnlyList<VideosWithIncludesVm>>(videos);

            var pagination = new PaginationVm<VideosWithIncludesVm>
            {
                Count = totalVideos,
                Data = data,
                PageCount = totalPages,
                PageIndex = request.PageIndex,
                PageSize = request.PageSize
            };

            return pagination;
        }
    }
}
