using CleanArchitecture.Application.Features.Actores.Queries.PaginationActor;
using CleanArchitecture.Application.Features.Actores.Queries.Vms;
using CleanArchitecture.Application.Features.Shared.Queries;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace CleanArchitecture.API.Controllers
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class ActorController: ControllerBase
    {
        private IMediator _mediator;

        public ActorController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet("pagination", Name ="PaginationActor")]
        [ProducesResponseType(typeof(PaginationVm<ActorVm>), (int)HttpStatusCode.OK)]
        public async Task<ActionResult<PaginationVm<ActorVm>>> GetPaginationActor(
            [FromQuery] PaginationActorQuery paginationActorParams)
        {
            var paginationActor = await _mediator.Send(paginationActorParams);
            return Ok(paginationActor);
        }

    }
}
