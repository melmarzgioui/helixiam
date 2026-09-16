package io.helixiam.persistence.filter;

import io.helixiam.persistence.DatabaseConstant;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;

public class FilterSpecification<T> implements Specification<T> {

    private static final Logger LOG = LogManager.getLogger(DatabaseConstant.MODULE_NAME);

    private final List<FilterCriteria> filterCriteriaList = new ArrayList<>();

    public FilterSpecification<T> add(final FilterCriteria filterCriteria) {
        filterCriteriaList.add(filterCriteria);
        return this;
    }

    @Override
    public Predicate toPredicate(final Root<T> root, final CriteriaQuery<?> query, final CriteriaBuilder criteriaBuilder) {
        if(!filterCriteriaList.isEmpty()) {
            final List<Predicate> predicates = new ArrayList<>();
            for(final FilterCriteria filterCriteria : filterCriteriaList) {
                switch (filterCriteria.operation()) {
                    case EQUALS -> predicates.add(criteriaBuilder.equal(root.get(filterCriteria.field()), filterCriteria.value()[0]));
                    case LIKE -> predicates.add(criteriaBuilder.like(root.get(filterCriteria.field()),  "%" + filterCriteria.value()[0].toString() + "%"));
                    default ->  LOG.warn("Unsupported criteria {}", filterCriteria.operation());
                }
            }

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        }

        return null;
    }
}
