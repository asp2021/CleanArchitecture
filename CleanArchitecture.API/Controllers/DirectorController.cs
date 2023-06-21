using CleanArchitecture.Application.Features.Directors.Commands.CreateDirector;
using CleanArchitecture.Application.Features.Directors.Queries.PaginationDirector;
using CleanArchitecture.Application.Features.Directors.Queries.Vms;
using CleanArchitecture.Application.Features.Shared.Queries;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace CleanArchitecture.API.Controllers
{
    [ApiController]
    [Route("api/v1/[controller]")]
    public class DirectorController : ControllerBase
    {
        private IMediator _mediator;

        public DirectorController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpGet("pagination", Name = "PaginationDirector")]
        [ProducesResponseType(typeof(PaginationVm<DirectorVm>), (int)HttpStatusCode.OK )]
        public async Task<ActionResult<PaginationVm<DirectorVm>>> GetPaginationDirector(
            [FromQuery]PaginationDirectorsQuery paginationDirectorsQuery)
        {
            var paginationDirector = await _mediator.Send(paginationDirectorsQuery);
            return Ok(paginationDirector);
        }

        [HttpPost(Name = "CreateDirector")]
        //[Authorize(Roles = "Administrator")]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        public async Task<ActionResult<int>> CreateDirector([FromBody] CreateDirectorCommand command)
        {
            return await _mediator.Send(command);
        }


    }
}
