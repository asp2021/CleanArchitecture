using CleanArchitecture.Application.Features.Actores.Queries.Vms;

namespace CleanArchitecture.Application.Features.Videos.Queries.Vms
{
    public class VideosWithIncludesVm
    {
        public string? Nombre { get; set; }
        public int StreamedId { get; set; }
        public string? StreamerNombre { get; set; }
        public int DirectorId { get; set; }
        public string? DirectorNombreCompleto { get; set; }

        public virtual ICollection<ActorVm>? Actores { get; set; }

    }
}
