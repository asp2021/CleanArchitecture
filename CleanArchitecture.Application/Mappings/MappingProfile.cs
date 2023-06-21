using AutoMapper;
using CleanArchitecture.Application.Features.Actores.Queries.Vms;
using CleanArchitecture.Application.Features.Directors.Commands.CreateDirector;
using CleanArchitecture.Application.Features.Directors.Queries.Vms;
using CleanArchitecture.Application.Features.Streamers.Commands;
using CleanArchitecture.Application.Features.Streamers.Commands.UpdateStreamer;
using CleanArchitecture.Application.Features.Streamers.Queries.Vms;
using CleanArchitecture.Application.Features.Videos.Queries.GetVideosList;
using CleanArchitecture.Application.Features.Videos.Queries.Vms;
using CleanArchitecture.Domain;

namespace CleanArchitecture.Application.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Video, VideosVm>();

            CreateMap<Video, VideosWithIncludesVm>()
                .ForMember( p=> p.DirectorNombreCompleto, x => x.MapFrom(a => a.Director!.NombreCompleto))
                .ForMember( p=>p.StreamerNombre, x=> x.MapFrom( a => a.Streamer!.Nombre))
                .ForMember( p=>p.Actores, x => x.MapFrom( a => a.Actores));

            CreateMap<Actor, ActorVm>();
            CreateMap<Director, DirectorVm>();
            CreateMap<Streamer, StreamersVm>();
            CreateMap<CreateStreamerCommand, Streamer>();
            CreateMap<UpdateStreamerCommand, Streamer>();
            CreateMap<CreateDirectorCommand, Director>();
        }
    }
}
