using CleanArchitecture.Application.Features.Streamers.Queries.Vms;
using MediatR;

namespace CleanArchitecture.Application.Features.Streamers.Queries.GetStreamerListByUsername
{
    public class GetStreamerListQuery: IRequest<List<StreamersVm>>
    {
         public string? Username { get; set; }

        public GetStreamerListQuery(string username)
        {
            Username = username ?? throw new ArgumentException(nameof(username));
        }
    }
}
