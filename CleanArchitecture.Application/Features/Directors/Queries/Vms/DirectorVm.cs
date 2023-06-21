namespace CleanArchitecture.Application.Features.Directors.Queries.Vms
{
    public class DirectorVm
    {
        public int Id {get; set;}
        public string? Nombre {get; set;}
        public string? Apellido { get; set; }
        public string? NombreCompleto { get; set; }
    }
}
