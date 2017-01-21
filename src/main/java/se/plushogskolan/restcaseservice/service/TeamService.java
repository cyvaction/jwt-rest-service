package se.plushogskolan.restcaseservice.service;

import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.NotFoundException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import se.plushogskolan.casemanagement.exception.AlreadyPersistedException;
import se.plushogskolan.casemanagement.exception.InternalErrorException;
import se.plushogskolan.casemanagement.exception.NotPersistedException;
import se.plushogskolan.casemanagement.model.Team;
import se.plushogskolan.casemanagement.service.CaseService;
import se.plushogskolan.restcaseservice.exception.ConflictException;
import se.plushogskolan.restcaseservice.exception.WebInternalErrorException;
import se.plushogskolan.restcaseservice.model.DTOTeam;

@Component
public class TeamService {

	private final CaseService service;

	@Autowired
	public TeamService(CaseService service) {
		this.service = service;
	}

	public Team save(DTOTeam dtoTeam) {
		try {
			return service.save(DTOTeam.toEntity(dtoTeam));
		} catch (AlreadyPersistedException e1) {
			throw new ConflictException("Team already exists");
		} catch (InternalErrorException e2) {
			throw new WebInternalErrorException("server error");
		}
	}

	public Team update(Long dtoTeamId, DTOTeam dtoTeam) {
		try {
			return service.updateTeam(dtoTeamId, DTOTeam.toEntity(dtoTeam));
		} catch (NotPersistedException e1) {
			throw new NotFoundException("Team does not exist");
		} catch (InternalErrorException e2) {
			throw new WebInternalErrorException("server error");
		}
	}

	public Team activateTeam(Long dtoTeamId, boolean isActive) {
		try {
			if (isActive) {
				return service.activateTeam(dtoTeamId);
			} else {
				return service.inactivateTeam(dtoTeamId);
			}
		} catch (InternalErrorException e1) {
			throw new WebInternalErrorException("server error");
		}
	}

	public DTOTeam getTeam(Long dtoTeamId) {
		try {
			return DTOTeam.toDTO(service.getTeam(dtoTeamId));
		} catch (NotPersistedException e1) {
			throw new NotFoundException("Team does not exist");
		} catch (InternalErrorException e2) {
			throw new WebInternalErrorException("server error");
		}
	}

	public List<DTOTeam> searchTeamByName(String name, int page, int size) {
		try {
			return teamListToDTOTeamList(service.searchTeamByName(name, page, size));
		} catch (InternalErrorException e1) {
			throw new WebInternalErrorException("server error");
		}
	}

	public List<DTOTeam> getAllTeams(int page, int size) {
		try {
			return teamListToDTOTeamList(service.getAllTeams(page, size));
		} catch (InternalErrorException e1) {
			throw new WebInternalErrorException("server error");
		}
	}

	private List<DTOTeam> teamListToDTOTeamList(List<Team> list) {
		List<DTOTeam> listDto = new ArrayList<>();
		for (Team user : list) {
			listDto.add(DTOTeam.toDTO(user));
		}

		return listDto;
	}

}
