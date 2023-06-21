using CleanArchitecture.Domain;

namespace CleanArchitecture.Application.Specifications.Actores
{
    public class ActorForCountingSpecification : BaseSpecification<Actor>
    {
        public ActorForCountingSpecification(ActorSpecificationParams actorParams)
            :base(
                 x=> 
                 string.IsNullOrEmpty(actorParams.Search) || x.Nombre!.Contains(actorParams.Search)
                 )
        {
        }
    }
}
