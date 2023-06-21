using CleanArchitecture.Domain;

namespace CleanArchitecture.Application.Specifications.Directores
{
    public class DirectorSpecification : BaseSpecification<Director>
    {
        public DirectorSpecification(DirectorSpecificationParams directorParams)
            :base(
                 x =>
                 string.IsNullOrEmpty(directorParams.Search) || x.Nombre!.Contains(directorParams.Search)
                 )
        {
            ApplyPaging(directorParams.PageSize * (directorParams.PageIndex - 1), directorParams.PageSize);

            if(!string.IsNullOrEmpty(directorParams.Sort))
            {
                switch(directorParams.Sort)
                {
                    case "nombreAsc":
                        AddOrderBy(p => p.Nombre!);
                        break;
                    case "nombreDesc":
                        AddOrderByDescending(p => p.Nombre!);
                        break;
                    case "apellidoAsc":
                        AddOrderBy(p => p.Apellido!);
                        break;
                    case "apellidoDesc":
                        AddOrderByDescending(p => p.Apellido!);
                        break;
                    case "createdDateAsc":
                        AddOrderBy(p => p.CreatedDate!);
                        break;
                    case "createdDateDesc":
                        AddOrderByDescending(p => p.CreatedDate!);
                        break;
                    case "idAsc":
                        AddOrderBy(p => p.Id!);
                        break;
                    case "idDesc":
                        AddOrderByDescending(p => p.Id!);
                        break;
                    default:
                        AddOrderBy(p => p.Nombre!);
                        break;
                }
            }
        }
    }
}
