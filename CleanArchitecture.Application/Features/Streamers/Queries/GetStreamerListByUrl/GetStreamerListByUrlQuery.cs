using CleanArchitecture.Application.Features.Streamers.Queries.Vms;
using MediatR;

namespace CleanArchitecture.Application.Features.Streamers.Queries.GetStreamerListByUrl
{
    public class GetStreamerListByUrlQuery: IRequest<List<StreamersVm>>
    {
        public string? Url { get; set; }

        public GetStreamerListByUrlQuery(string? url)
        {
            Url = url ?? throw new ArgumentNullException(nameof(url));
        }
    }
}
